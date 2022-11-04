// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file sspi.c
 *
 * @brief MPTCP single-subflow-per-interface path manager plugin.
 *
 * Copyright (c) 2018-2021, Intel Corporation
 */

#ifdef HAVE_CONFIG_H
# include <mptcpd/private/config.h>  // For NDEBUG and mptcpd VERSION.
#endif

#include <assert.h>
#include <stddef.h>  // For NULL.
#include <limits.h>
#include <netinet/in.h>
#include <ell/util.h>  // For L_STRINGIFY needed by l_error().
#include <ell/log.h>
#include <ell/queue.h>
#include <mptcpd/network_monitor.h>
#include <mptcpd/path_manager.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <mptcpd/addr_info.h>
#include <mptcpd/plugin.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>  // exit()
#include <sys/wait.h>
#include "mptcpd/mptcp_ns3.h"
#include "mptcpd/private/addr_info.h"
#include "mptcpd/private/sockaddr.h"

// #define USE_CORE  

/*
*******************************************************************
*      Data Struct
* ******************************************************************
*/

/**
 * @brief Local address to interface mapping failure value.
 */
#define SSPI_BAD_INDEX INT_MAX

/**
 * @struct sspi_subflow_info
 *
 * @brief MPTCP subflow information.
 *
 * This plugin tracks and controlls MPTCP subflow for each network
 * connection. A subflow is represented by its token, mptcp address ID pairs,  
 * local/remote address of the subflow and backup flag.  
 * Subflow is controlled by decision algorithm. Basically we need to save new 
 * subflow into the list, control subflow usage (priority) durring connection,
 * and remove subflow(s) from the list when connection is closed.   
 * */

struct sspi_subflow_info {
        mptcpd_token_t token;           // connection id 
        mptcpd_aid_t l_id;              // local address id  (1 and 2)
        mptcpd_aid_t r_id;              // remote address id (received from peer)
        struct sockaddr const *laddr;   // local IP addr
        struct sockaddr const *raddr;   // remote IP addr 
        bool backup;                    // is subflow backup priority flag
        bool active;                    // is sf avilable for interaction 
        //time_t last_backup            // time(0) last time backup flag changed
        //time_t last_active time(0)    // last time active flag changed 
        double last_score ;          // save last score for this sf
}; 

// save score value for each network for the specific service 
struct sspi_service {
        double score_wlan; 
        double score_lte; 
};

// data to be passed to for_each function to manage subflows
struct sspi_sf_manage_data {
        struct sspi_service const * s_list;   // list of scores for each service/network 
        struct mptcpd_pm *const pm;           // path manager 
}; 

/*****
 * List of @c sspi_subflow_info objects that contain MPTCP subflows of each
 * ongoing connection.
 */
static struct l_queue *sspi_subflows;

/**
 * @brief List of @c mptcpd_addr_info data saved when plugin init
 */
static struct l_queue *sspi_interfaces;



/*
*******************************************************************
*      Additional functions
* ******************************************************************
*/

uint16_t sspi_get_port_number(struct sockaddr const *addr)
{
        in_port_t port = 0;

        if (addr == NULL)
                return port;

        if (addr->sa_family == AF_INET) {
                struct sockaddr_in const *const addr4 =
                        (struct sockaddr_in const*) addr;

                port = addr4->sin_port;

        } else if (addr->sa_family == AF_INET6) {
                struct sockaddr_in6 const *const addr6 =
                        (struct sockaddr_in6 const*) addr;

                port = addr6->sin6_port;
        }

        return ntohs(port);
}

/**
 * @brief Match a @c sockaddr object.
 *
 * A network address represented by @a a (@c struct @c sockaddr)
 * matches if its @c family and @c addr members match those in the
 * @a b.
 *
 * @param[in] a Currently monitored network address of type @c struct
 *              @c sockaddr*.
 * @param[in] b Network address of type @c struct @c sockaddr*
 *              to be compared against network address @a a.
 *
 * @return @c true if the network address represented by @a a matches
 *         the address @a b, and @c false otherwise.
 *
 * @see l_queue_find()
 * @see l_queue_remove_if()
 */
static bool sspi_sockaddr_match(void const *a, void const *b)
{
        struct sockaddr const *const lhs = a;
        struct sockaddr const *const rhs = b;

        assert(lhs);
        assert(rhs);
        assert(lhs->sa_family == AF_INET || lhs->sa_family == AF_INET6);

        bool matched = (lhs->sa_family == rhs->sa_family);

        if (!matched)
                return matched;

        if (lhs->sa_family == AF_INET) {
                struct sockaddr_in const *const l =
                        (struct sockaddr_in const *) lhs;
                struct sockaddr_in const *const r =
                        (struct sockaddr_in const *) rhs;
                matched = ( (l->sin_addr.s_addr == r->sin_addr.s_addr) 
                            //&& (l->sin_port == r->sin_port) 
                            )    ;
        } else {
                struct sockaddr_in6 const *const l =
                        (struct sockaddr_in6 const *) lhs;
                struct sockaddr_in6 const *const r =
                        (struct sockaddr_in6 const *) rhs;

                matched = (memcmp(&l->sin6_addr,
                                  &r->sin6_addr,
                                  sizeof(l->sin6_addr))
                                   == 0);
        }

        return matched;
}

// debug functio print ipv4 addr in hex
__attribute__((unused)) static void
sspi_sock_addr_print(struct sockaddr const *addr)
{
        char s[12] = { 0 };
        sprintf(s,
                "%02X:%02X:%02X:%02X",
                addr->sa_data[2],
                addr->sa_data[3],
                addr->sa_data[4],
                addr->sa_data[5]);
        l_info ("%s",s); 
}

/********************************************************************/
/*               FAHP decision process                           */
/********************************************************************/


/*
        utility functions benefit / cost
*/
static double sspi_ahp_bilateral_ben (double val, double a, double b){
        double e =  2.718281828459045; 
        double p = -1*a * (val-b); 
        return 1 / (1 + pow(e,p)); 
}
static double sspi_ahp_bilateral_cost (double val, double a, double b){
        return 1 - sspi_ahp_bilateral_ben (val, a, b); 
}
static double sspi_ahp_unilateral_ben (double val, double g){
        assert(val); 
        return 1 - (g/val); 
}
static double sspi_ahp_unilateral_cost (double val, double g){
        return 1 - (g*val); 
}

/*
        calculate score by multiplying weigths vector and attributes 
*/
static double sspi_ahp_get_score (const double a[], const double w[], size_t size){
        double res = 0.0;
        for (size_t i=0; i < size; i++){
                res+= a[i]*w[i]; 
        }
        if (res < 0.0) res = 0.0;  
        return res; 
}

/*
        Functions to calculate score for each service
*/

static double sspi_ahp_service_max (double attr[], size_t size){
         // normalized weigths for max thput services  
        const double norm[] = 
                {0.29, 0.104, 0.027, 0.401, 0.079, 0.1}; 
        
        attr[0] = sspi_ahp_bilateral_ben(attr[0], 0.15, -80);   // rss   [-100 : -30 dBm]
        attr[1] = sspi_ahp_bilateral_cost(attr[1], 0.03, 250);  // delay [ 100: 400 ms]
        attr[2] = sspi_ahp_bilateral_cost(attr[2], 0.07, 60);   // jitter  [10 : 150 ms]
        attr[3] = sspi_ahp_unilateral_cost(attr[3], 1.0/15);      // plr [ <15 %]
        attr[4] = sspi_ahp_unilateral_cost(attr[4], 1.0/SSPI_LINK_COST_MAX);  
        attr[5] = sspi_ahp_unilateral_ben(attr[5], 5);          // dweel  [> 5 s]

        return sspi_ahp_get_score(attr, norm, size); 
}

/**
 * @brief FAHP decision procedure.. calculate and save final scores for 
 * each service for each network interface. 
 * Attributes to concider :  RSSI, Latency, Jitter, PLR, Cost, Dwell Time
 * @param msg msg from ns-3 
 * @return 
 */

static void sspi_ahp_decision (const struct sspi_data_message *msg, 
                                struct sspi_service list[]) 
{
        // save received metrics 
        double wlan_m [] = {0, 0, 0, 0, 0, 0}; 
        double lte_m []  = {0, 0, 0, 0, 0, 0};

        wlan_m[0] = msg->phy_wlan.signal;       // [dBm]
        wlan_m[1] = msg->flow_wlan.delay;       // ms
        wlan_m[2] = msg->flow_wlan.jitter;      // ms
        wlan_m[3] = msg->flow_wlan.plr;         // %
        wlan_m[4] = msg->phy_wlan.cost;         // int 
        wlan_m[5] = msg->phy_wlan.dweel_time;   // [s]

        lte_m[0] = msg->phy_lte.signal;  
        lte_m[1] = msg->flow_lte.delay;  
        lte_m[2] = msg->flow_lte.jitter;  
        lte_m[3] = msg->flow_lte.plr;  
        lte_m[4] = msg->phy_lte.cost;  
        lte_m[5] = msg->phy_lte.dweel_time; 

        size_t w_size = sizeof (wlan_m)/sizeof(wlan_m[0]);  

        // calculate score for each network for each service 
        for (int service = 0; service < SSPI_SERVICE_LAST; service ++) {

                list[service].score_wlan = 0.0;
                list[service].score_lte = 0.0;

                switch (service) {
                case SSPI_SERVICE_MAX:
                        if (msg->phy_wlan.is_connected) {
                                list[service].score_wlan = 
                                        sspi_ahp_service_max(wlan_m, w_size);
                        }
                        if (msg->phy_lte.is_connected) {
                                list[service].score_lte  = 
                                        sspi_ahp_service_max(lte_m, w_size);
                        }
                        break;
                // case SSPI_OTHER_SERVICE 
                default:
                        break;
                }
        }
        
}


/********************************************************************/
/*               LIMITS: set initilal mptcp params                          */
/********************************************************************/

__attribute__((unused)) 
static void sspi_empty_callback(void* data){
    (void) data ; 
}

static void sspi_get_limits_callback(struct mptcpd_limit const *limits,
                                size_t len,
                                void *user_data)
{
        if (geteuid() != 0) {
                /*
                  if the current user is not root, the previous set_limit()
                  call is failied with ENOPERM, but libell APIs don't
                  allow reporting such error to the caller.
                  Just assume set_limits has no effect
                */
                l_info ("uid != 0"); 
        }

        (void) user_data;
        uint16_t _addr,_subf; 
        for (struct mptcpd_limit const *l = limits; l != limits + len; ++l) {
                if (l->type == MPTCPD_LIMIT_RCV_ADD_ADDRS) {
                        _addr =  l->limit;  
                } else if (l->type == MPTCPD_LIMIT_SUBFLOWS) {
                        _subf = l->limit; 
                } else {
                        l_error("Unexpected MPTCP limit type.");
                }
        }
        l_info ("ADD_ADDR: %u, SUBF: %u", _addr, _subf);
}

/**
 * @brief Set MPTCP Subflow Limits when plugin is loaded 
 * @param in is path manager 
 *  
 */
static void sspi_set_limits(void const *in)
{
        struct mptcpd_limit const _limits[] = {
                { .type  = MPTCPD_LIMIT_RCV_ADD_ADDRS,
                  .limit = SSPI_MAX_ADDR },
                { .type  = MPTCPD_LIMIT_SUBFLOWS,
                  .limit = SSPI_MAX_SUBFLOWS }
        };

        if (in == NULL)  return;

        struct mptcpd_pm *const pm = (struct mptcpd_pm *) in;
        if (mptcpd_kpm_set_limits(pm, _limits, L_ARRAY_SIZE(_limits))) {
                l_error("Cannot set limits");
        }
}


/********************************************************************/
//                  SUBFLOWS                                         /
/********************************************************************/
// Destroy @c sspi_subflow_info objects in list of subflow on exit
// @see l_queue_destroy() 
static void sspi_sf_destroy(void *p)
{
        if (p == NULL) return;
        struct sspi_subflow_info *const info = p;
        l_free(info);
}


// show mptcp interfaces id and index (debug func)
// @see l_queue_foreach()
static void sspi_foreach_sf_show(void *data, void *user_data)
{
    (void) user_data; 
    struct sspi_subflow_info const *const sf = data;

    l_info ("ID: %u, token: %u, backup: %u, active: %u", 
                                sf->l_id, sf->token, sf->backup, sf->active);
    //sspi_sock_addr_print(sf->laddr);
    //sspi_sock_addr_print(sf->raddr);
}

/**
 * @brief Match @c mptcpd_token_t tokens
 * When MPTCP connection is closed we need to remove all assotiated subflows 
 * thus we run l_queue_foreach_remove
 * 
 * @param a @c sspi_subflow_info 
 * @param b @c mptcp_token_t 
 * @return true if token of subflow_info matches provided token in @a b 
 * 
 * @see l_queue_foreach_remove()
 */
bool sspi_sf_remove(void *data, void *user_data)
{
        assert(data);
        assert(user_data);

        struct sspi_subflow_info *const info = data;
        return info->token == L_PTR_TO_UINT(user_data); 
}


/**
 * @brief Match a MPTCP subflow with l_id=ID. 
 * l_id for LTE =  SSPI_IFACE_LTE=1, for SSPI_IFACE_WLAN=2. 
 * @return @c true if the MPTCP subflow l_id @a a matches the user 
 * supplied ID @a b, and @c false otherwise.
 */
static bool sspi_sf_id_match(void const *a, void const *b)
{
        assert(a);
        assert(b);

        struct sspi_subflow_info const *const info = a;
        mptcpd_aid_t const *const b_id = b;
        return info->l_id == *b_id;
}

/**
 * @brief Match all values of a MPTCP subflow @c (struct sspi_subflow_info). 
 * @return @c true if the MPTCP subflow a matches the user 
 * supplied info, and @c false otherwise.
 */
static bool sspi_sf_match(void const *a, void const *b)
{
        assert(a);
        assert(b);

        struct sspi_subflow_info const *const sf_a = a;
        struct sspi_subflow_info const *const sf_b = b;
        return (sf_a->token == sf_b->token)
            && (sf_a->l_id == sf_b->l_id)
            && (sf_a->r_id == sf_b->r_id) 
            && (sspi_sockaddr_match (sf_a->laddr, sf_b->laddr))
            && (sspi_sockaddr_match (sf_a->raddr, sf_b->raddr));
}

/**
 * @brief  Create @c sspi_subflow_info struct and save new subflow into subflows list
 * 
 * @param token connection tocken id 
 * @param laddr local addr 
 * @param raddr remote addr 
 * @param id mptcp endpoint. l_id = r_id. could be SSPI_IFACE_WLAN or SSPI_IFACE_LTE 
 * ID is nedded to identify network: assuming initial connection maded through 
 * LTE subflow assuming additional connection on WLAN
 * @param backup flag of sf 
 * @param active is subflow activation was confirmed with ACK thoroug new_subflow
 * callback func 
 *   
 */
static void sspi_sf_add( mptcpd_token_t token,
                                struct sockaddr const *laddr,
                                struct sockaddr const *raddr, 
                                mptcpd_aid_t l_id,
                                mptcpd_aid_t r_id,
                                bool backup, 
                                bool active)
{
        struct sspi_subflow_info *const info =
                l_malloc(sizeof(struct sspi_subflow_info));

        info->l_id              = l_id;
        info->r_id              = r_id;
        info->token             = token;
        info->backup            = backup;
        info->laddr             = mptcpd_sockaddr_copy(laddr);
        info->raddr             = mptcpd_sockaddr_copy(raddr);
        info->active            = active;
        info->last_score        = 0.0;  
        
        // check IF same sobflow already exist
        struct sspi_subflow_info *sf =
                l_queue_find(sspi_subflows, sspi_sf_match, info);

        // sf not found: push new subflow into the list if not exists
        if (sf == NULL){
                l_queue_push_tail(sspi_subflows, (void *) info);
        }
        // sf found, just change status information of the existing sf
        else {
                // sf->backup = backup; // receive bkp=1 always on new_subflow callback 
                // l_info ("sf add l_id: %u, bkp: %u", l_id, backup); 
                sf->active = active;
                l_free(info);
                // todo : check timestamp 
                // time_t t1 = time(0);
                // double datetime_diff_ms = difftime(t1, t0) * 1000.;
        }

        // debug 
        puts ("Print SF list : "); 
        l_queue_foreach (sspi_subflows, sspi_foreach_sf_show, NULL); 
        puts(""); 
}


/**
 * @brief mange subflows usage after score is calculated. 
 * 
 * @param data is next sf from list  @see l_queue_foreach()
 * @param user_data struct sspi_service_list with score info for each service/network
 */

static void sspi_sf_manage (void *data, void *user_data)
{
    if (data == NULL || user_data == NULL) return; 
    struct sspi_sf_manage_data *m_data = user_data; // list of scores & pm
    struct sspi_subflow_info *const sf = data;      // next sf from list 

    // list of scores for each service/network
    struct sspi_service const *s_list   = m_data->s_list;
    struct mptcpd_pm *const pm          = m_data->pm;

    const double LOW_SCORE      = 0.25;     
    const double MEDIUM_SCORE   = 0.50;
    //const double HIGH_SCORE     = 0.85;      
    const double DELTA_SCORE    = 0.05;  // delta 5% ( TODO could vary with velocity)

    uint16_t const port = sspi_get_port_number(sf->raddr);

    // get right service based on port numver 
    enum sspi_services service;
    switch (port) {
    case 5001:                                  //max thput service:
            service = SSPI_SERVICE_MAX;
            break;
    // other services here
    default:
            l_error("Uknow service %u", port);
            return;
    }
    
    // get right score value for selected service for first and second networks 
    double score_first, score_second;
    switch (sf->l_id)
    {
    case SSPI_IFACE_LTE:
        score_first = s_list[service].score_lte;
        score_second = s_list[service].score_wlan;
        break;
    case SSPI_IFACE_WLAN:
        score_first = s_list[service].score_wlan;
        score_second = s_list[service].score_lte;
        break;
    default:
        l_error ("Undefined local id: %u", sf->l_id); 
        return;
    }
         // debug 
    l_info("ID: %u, token: %u, backup: %u, port:%u, active: %u, f: %2f, s :%2f ",
           sf->l_id, sf->token, sf->backup, port, sf->active, score_first, score_second);
    
    
    // calculate DELTA score, exit if score changes is insignificant 
    double s_delta =  sf->last_score - score_first; 
    s_delta = (s_delta < 0)? s_delta * (-1.0) : s_delta;
    if (s_delta < DELTA_SCORE) return;  

    // remove active sf with low score, and set as non active 
    if (score_first < LOW_SCORE && sf->active) {
        if (mptcpd_pm_remove_subflow( pm, sf->token, sf->laddr, sf->raddr)!= 0)
                l_error("Can't remove subflow %u", sf->token);
        l_info ("SHOULD Remove sf : %u l_id: %u, but NOT WORKS", sf->token, sf->l_id); 
        //sf->active = false;
    }

    // else if sf not active : create sf and activate it
    else if (score_first >= LOW_SCORE && !sf->active) {
            // define backup flag based on calculated score 
            bool backup = (score_first < MEDIUM_SCORE) ? true : false;
            // will invoce new_subflow callback on sucess sf creation
            if (mptcpd_pm_add_subflow( pm, sf->token, sf->l_id, sf->r_id,
                        sf->laddr, sf->raddr, backup) != 0)
                    l_error("Can't create subflow %u", sf->token);

            l_info ("Create sf token:%u bkp:%i", sf->token, backup);  
            // TODO : should set active on confirmed sf creation: 
            // callback function new_subflow..
            // requires some timer/flag system to control async calls..
            // for now assume sf is created 100%
            sf->active = true;
            sf->backup = backup; 
    }

    // sf is active : control sf backup status based on scores
    else if (sf->active){
            bool backup = (score_first < MEDIUM_SCORE) ? true : false;
            if (sf->backup != backup){
                if (mptcpd_pm_set_backup(pm, sf->token, sf->laddr,
                                        sf->raddr, backup) != 0) {
                        l_error("Can't change backup status to %u", backup);
                }
                    // callback is not involved in this case: assume msg sent
                    l_info ("Set backup l_id:%u bkp:%i", sf->l_id, backup);  
                    sf->backup = backup;
            }
    } 
    
    else {
            // nothing to do
            return;
    }

    sf->last_score = score_first; 
}


/********************************************************************/
//                  Interfaces                                       /
/********************************************************************/

// show mptcp interfaces id and index (debug func)
// static void sspi_interfaces_foreach(void *data, void *user_data)
// {
//     (void) user_data; 
//     struct mptcpd_addr_info const *const addr = data;

    
//     l_info ("ID %u index %d", 
//                 mptcpd_addr_info_get_id (addr),
//                 mptcpd_addr_info_get_index(addr));   

// }

// called when addresses are dumped (debug func)
static void dump_addrs_complete(void *user_data)
{
        (void)user_data; 
        l_info ("DUMPED addrs in= %u", l_queue_length(sspi_interfaces));
       // l_queue_foreach(sspi_interfaces, sspi_interface_foreach,NULL);
}

// Destroy mptcp_addr_info objects in list of interfaces on exit 
static void sspi_interface_info_destroy(void *p)
{
        if (p == NULL) return;
        struct mptcpd_addr_info *const info = p;
        l_free(info);
}

/**
 * Dump addresess and save into @c sspi_interfaces list 
 * create @c mptcp_addr_info object and push it to the interfaces list  
 */
static void sspi_dump_addrs_callback(struct mptcpd_addr_info const *info,
                                void *user_data)
{
        (void) user_data;
        void *i = l_memdup( (void*)info, sizeof(struct mptcpd_addr_info)); 
        l_queue_push_tail (sspi_interfaces, i); 
}


/**
 * @brief Match a MPTCP interface ID .
 * @return @c true if the MPTCP inetraface in the @c sspi_interface_info object
 * @a a matches the user supplied ID @a b, and @c false otherwise.
 */
static bool sspi_interface_id_match(void const *a, void const *b)
{
        assert(a);
        assert(b);

        struct mptcpd_addr_info const *const info = a;
        mptcpd_aid_t a_id = mptcpd_addr_info_get_id (info); 
        mptcpd_aid_t const *const b_id = b;

        return a_id == *b_id;
}

/**
 * @brief find in list of interfaces addr_info that match addr of type sockaddr
 *  used to find interface addr_info based on laddr in connection_established function 
 * @param a 
 * @param b sockaddr to find 
 * @see l_queue_find()
 */
static bool sspi_interface_addr_match(void const *a, void const *b)
{
        assert(a);
        assert(b);

        struct mptcpd_addr_info const *const info = a;
        struct sockaddr const *a_addr = mptcpd_addr_info_get_addr(info); 
        struct sockaddr const *b_addr = b;

        return sspi_sockaddr_match(a_addr, b_addr);
}

/*************************************************************************************/
/**                           COMMANDs                                                */
/*************************************************************************************/

/**
 * @brief parsing incoming COMMAND message  
 * 
 * @param msg message to be parsed 
 * @param in pointer to struct mptcpd_pm *const, need cast from void
 * 
 * @return -1 if receives "end" command from mptcpd main therad.. 
 *              0 othervise   
 */
static int 
sspi_msg_cmd_parse (struct sspi_cmd_message* msg, void* in){
 
        struct mptcpd_pm *const pm = (struct mptcpd_pm *)in;
        l_info ("CMD: %d value: %d", msg->cmd, msg->cmd_value);

        // struct mptcpd_pm *const pm = (struct mptcpd_pm *)in;
        
        /** 
		 * 05 cmd from mptcpd to stop thread (called on Cntr+C)
		*/
        if (msg->cmd == SSPI_CMD_STOP_RV_MSG) {
				int pid;
				//  remove zombies on exit, or each time when receive CMD ??   
                while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
                        //printf("child %d terminated\n", pid);
                }
                return -1; // break reading loop
        }

        // 01 START tcpdump recording durring the simulation */
        else if( msg->cmd == SSPI_CMD_TCPDUMP){
			  if (fork() == 0) {
			  		char buf [64];
					sprintf(buf, "%d", msg->cmd_value);

                    execl("/usr/bin/timeout", "timeout", "--signal=KILL", buf,
							"tcpdump", "-s",  "100", "-i", "any", 
							"-w", "/home/vad/dump.pcap", (char *)0); 
              }
        
        }
        // 02 create sf on id=cmd_value endpoint
        // echo -en "\01\02\00\00\00\00\c" > /tmp/mptcp-ns3-fifo 
        else if (msg->cmd == SSPI_CMD_CREATE_SF){

            // get last entry from sf list (should be non active) 
            struct sspi_subflow_info *info = 
                    l_queue_peek_tail (sspi_subflows);
            assert(info);
            if (!info->active) {
                    if (mptcpd_pm_add_subflow(pm,
                                              info->token,
                                              info->l_id,
                                              info->r_id,
                                              info->laddr,
                                              info->raddr,
                                              false)
                        != 0)
                            l_error("can't create new subflow %u",
                                    info->token);
            }
        }

        /**
         *  will set all subflows with l_id=2 to backup
         *  echo -en "\01\03\00\00\00\02\c" > /tmp/mptcp-ns3-fifo
         * */
        else if (msg->cmd == SSPI_CMD_BACKUP_ON) {
                
                //  mptcp endpoint ID to be changed
                mptcpd_aid_t id = (uint8_t) msg->cmd_value;

                struct sspi_subflow_info *info =
                        l_queue_find(sspi_subflows,
                                     sspi_sf_id_match,
                                     &id);
                assert(info); 

                if (info->backup || mptcpd_pm_set_backup(pm,
                                            info->token,
                                            info->laddr,
                                            info->raddr,
                                            true) !=0)
                {
                    l_error ("Can't set backup on subflow in %u",
                    info->token);
                }

                info->backup = true; 
        }

          /**
         *  remove backup flag on all subflows with l_id=2 
         *  echo -en "\01\04\00\00\00\02\c" > /tmp/mptcp-ns3-fifo
         * */
        else if (msg->cmd == SSPI_CMD_BACKUP_OFF) {
                //  subflow ID to be changed
                mptcpd_aid_t id = (uint8_t) msg->cmd_value;
                
                struct sspi_subflow_info *info =
                        l_queue_find(sspi_subflows,
                                     sspi_sf_id_match,
                                     &id);
                assert(info); 

                if (!info->backup || mptcpd_pm_set_backup(pm,
                                            info->token,
                                            info->laddr,
                                            info->raddr,
                                            false) !=0)
                {
                    l_error ("Can't remove backup on subflow in %u",
                    info->token);
                }

                info->backup = false; 
        }

        /**
         *  remove  on all subflows with l_id=2 
         *  echo -en "\01\07\00\00\00\02\c" > /tmp/mptcp-ns3-fifo
         * */
        else if (msg->cmd == SSPI_CMD_REMOVE_SF) {
                //  subflow ID to be changed
                mptcpd_aid_t l_id = (uint8_t) msg->cmd_value;                
                struct sspi_subflow_info *info =
                        l_queue_find(sspi_subflows,
                                     sspi_sf_id_match,
                                     &l_id);
                assert(info); 

                // remove only initial first sf (id = 1), if another created 
                if (mptcpd_pm_remove_subflow(pm,
                                            info->token,
                                            info->laddr,
                                            info->raddr) !=0) {
                        l_error ("Can't remove subflow in %u",
                        info->token);

                } else {
                        l_info("SSPI_CMD_REMOVE_SF:%d", l_id);
                        info->active = false;
                }

                // nothing 
                // if (mptcpd_kpm_remove_addr(pm,id)){
                //     l_error ("Can't REMOVE_ADDR id: %u", id); 
                // }

                 
        }

        /**
         * @brief stert generate traffic in separate process
         * echo -en "\01\06\00\00\00\05\c" > /tmp/mptcp-ns3-fifo 
         * generate mptcp traffic for 5 sec 
         */
        else if (msg->cmd == SSPI_CMD_IPERF_START) {
            if (fork() == 0) {
                char buf[64];
		sprintf(buf,"iperf -c 13.0.0.2 -e -i1 -t %d > /dev/null ", msg->cmd_value); 
                l_info("%s", buf);
		execl ("/home/vad/mptcp-tools/use_mptcp/use_mptcp.sh", 
						"use_mptcp.sh", 
						buf,   (char *)0);
                }
                
        } else {
                // just inform user, continue to reading 
                l_info("Uknown CMD msg : %d", msg->cmd);
        }

        return EXIT_SUCCESS; 
}

/*****************************************************************************************/ 
/*****************************************************************************************/ 

/**
 * @brief receive and parse data from NS-3. Calculate network score and 
 * make PM decisions based on received attributes 
 * 
 * @param msg data from ns-3, i.e., rssi, speed, ..
 * @param in mptcpd_pm 
 * @return 0 on sucess , -1 on failure 
 */
static int 
sspi_msg_data_parse (struct sspi_data_message* msg, void* in ){
        
        struct mptcpd_pm *const pm = (struct mptcpd_pm *)in;
        
        // l_info("Received WLAN data-> signal: %f, rsu_connected: %i, dweel time: %f", 
        //                     msg->phy_wlan.signal, msg->phy_wlan.is_connected, msg->phy_wlan.dweel_time);
        // No active connections, nothing to manage
        if (l_queue_isempty(sspi_subflows)){
            return EXIT_SUCCESS;
        }
        
        // 1. calculate the score for each service/network and save in list 
        struct sspi_service s_list [SSPI_SERVICE_LAST];  
        sspi_ahp_decision (msg, s_list);

        // don't manage sf if using CORE emulation scenario 
        #ifdef USE_CORE
                (void) pm;
                sspi_sf_manage (NULL, NULL);
                return EXIT_SUCCESS;  
        #endif

        #ifndef USE_CORE
                /// 2. for each subflow decide wich network to use, by
                /// evaluate the score in FAHP procedure 
                struct sspi_sf_manage_data m_data = { .s_list = s_list,
                                                      .pm     = pm };
                l_queue_foreach(sspi_subflows, sspi_sf_manage, &m_data);
        #endif

        return EXIT_SUCCESS;
} 


/*****************************************************************************************/
//                     Mptcpd Plugin Operations
/*****************************************************************************************/

static void sspi_new_connection(mptcpd_token_t token,
                                struct sockaddr const *laddr,
                                struct sockaddr const *raddr,
                                bool server_side,
                                struct mptcpd_pm *pm)
{
        l_info("NEW CONNECTION : token = %u, server_side = %d ",
               token,
               server_side);
        
        (void) server_side; 
        (void) token;
        (void) laddr;
        (void) raddr;
        (void) pm;
      
}

/**
 *  New MPTCP connection established:
 *  Create @c sspi_subflow_info struct and save (main) subflow to subflows list
 */

static void sspi_connection_established(mptcpd_token_t token,
                                        struct sockaddr const *laddr,
                                        struct sockaddr const *raddr,
                                        bool server_side, 
                                        struct mptcpd_pm *pm)
{
        
        // find interface addr_info that have laddr
        // THIS IS NOT USED 
        struct mptcpd_addr_info *info = l_queue_find( sspi_interfaces, 
                                            sspi_interface_addr_match, 
                                            laddr);
        assert(info);
        // // get interface id from addr_info 
        // mptcpd_aid_t l_id = mptcpd_addr_info_get_id (info);
        // if (!l_id) l_error ("ERROR: endpoint id is 0"); 
        
        // TODO:: we know initial endpoint, thus we receive ADD_ADDR on other endpoin 
        // that is left, so save this information to use it in sspi_new_address
        // and don't use hardkoded SSPI_IFACE_WLAN vale.. where to save?

        // NOW we just assume initial connection on LTE path 
        mptcpd_aid_t l_id = SSPI_IFACE_LTE;  
        mptcpd_aid_t r_id = SSPI_IFACE_LTE;  
         
        l_info("ESTABLISHED: token = %u, endp id=%u", token, l_id);

        // create initial 'active' , 'no backup' subflow on LTE interface
        sspi_sf_add (token,laddr,raddr,l_id, r_id, false, true); 

        (void) server_side;  
        (void) pm;
}

static void sspi_connection_closed(mptcpd_token_t token,
                                   struct mptcpd_pm *pm)
{   
        l_info ("CONNECTION CLOSED: token %u", token);

        // Remove all sspi_subflow_info objects associated with the
        // given MPTCP token.
        if (l_queue_foreach_remove(sspi_subflows,
                                   sspi_sf_remove,
                                   L_UINT_TO_PTR(token)) == 0)
                l_error("Untracked connection closed.");

        (void) pm;      
}

/**
 * We receive ADD_ADDR from pear : 
 * do not establish new subflow on WLAN, just save the data on subflows list.
 * new sf will be created after decision algorithm order to do it  
 */
static void sspi_new_address(mptcpd_token_t token,
                             mptcpd_aid_t r_id,
                             struct sockaddr const *r_addr,
                             struct mptcpd_pm *pm)
{
        l_info ("NEW ADD_ADDR: token = %u , remote id = %u", token, r_id);
        
        // assume WLAN iface used to create additional sf's 
        mptcpd_aid_t l_id_wlan = SSPI_IFACE_WLAN; 
    
        // find local addr of wlan interface by looking of wlan id 
        struct mptcpd_addr_info *inf = l_queue_find(sspi_interfaces, 
                                            sspi_interface_id_match, 
                                            &l_id_wlan);
        assert(inf);
        struct sockaddr const *l_addr = mptcpd_addr_info_get_addr(inf); 
        assert(l_addr); 
        
        // struct sockaddr *const raddr = mptcpd_sockaddr_copy(addr); 

        // Do not establish new subflow connection just create record about 
        // potential subflow, mark sf as 'non active', so we can use it 
        // to create new subflows when decision algorithm order it..
        // TODO: get mptcp endpoint by lokking on *laddr, and interfaces list    
        sspi_sf_add (token, l_addr, r_addr, l_id_wlan, r_id, false, false);
        (void) pm; 
        
        /**
         * @TODO should be, try to create sf for each avilable address that are 
         * not already in connection. 
         * interfaces list should be updated every time, since new adresses may
         * appear.. see sspi_old..  
         */
}

static void sspi_address_removed(mptcpd_token_t token,
                                 mptcpd_aid_t id,
                                 struct mptcpd_pm *pm)
{
        /*
          The sspi plugin doesn't do anything with addresses that are
          no longer advertised.
        */
        l_info ("ADDR REMOVED");
        (void) token;
        (void) id;
        (void) pm;

}

/**
 * New subflow estableshid :
 * Create @c sspi_subflow_info struct and save new subflow into subflows list
 */

static void sspi_new_subflow(mptcpd_token_t token,
                             struct sockaddr const *laddr,
                             struct sockaddr const *raddr,
                             bool backup,
                             struct mptcpd_pm *pm)
{
        l_info("NEW SUBFLOW: token: %u " , token);

        // assume addirional sf's on WLAN iface
        mptcpd_aid_t l_id = SSPI_IFACE_WLAN;
        mptcpd_aid_t r_id = SSPI_IFACE_WLAN;

        // Update sf status to active.. 
        // TODO: Should be another function that update active status
        // based only on l_addr and r_addr info  
        // because sf entry was already created on new_address callback
        sspi_sf_add (token, laddr, raddr, l_id, r_id, backup, true); 
        (void) pm;
}

static void sspi_subflow_closed(mptcpd_token_t token,
                                struct sockaddr const *laddr,
                                struct sockaddr const *raddr,
                                bool backup,
                                struct mptcpd_pm *pm)
{
        l_info ("SUBFLOW CLOSED");
        (void) raddr;
        (void) backup;
        (void) laddr; 
        (void) pm; 
        (void) token; 
}


static void sspi_subflow_priority(mptcpd_token_t token,
                                  struct sockaddr const *laddr,
                                  struct sockaddr const *raddr,
                                  bool backup,
                                  struct mptcpd_pm *pm)
{
        /*
            Plugin does not invoce this callback on client side, when client 
            initialize sf priority changes.
        */
        l_info ("SUBFLOW PRIORITY");
        (void) token;
        (void) laddr;
        (void) raddr;
        (void) backup;
        (void) pm;
        
}

/*****************************************************************************************/
//                  network monitor event handlers 
/*****************************************************************************************/

static void sspi_new_interface (struct mptcpd_interface const *i,
                                struct mptcpd_pm *pm){

        l_info ("NEW INTERFACE"); 
        (void) i; 
        (void) pm; 
}

static void sspi_update_interface (struct mptcpd_interface const *i,
                         struct mptcpd_pm *pm)
{
        l_info ("UPDATE interface");
        (void) i; 
        (void) pm;  
}

static void sspi_delete_interface(struct mptcpd_interface const *i,
                                  struct mptcpd_pm *pm)
{
        l_info("INTEFACE REMOVED");
        (void) i; 
        (void) pm; 
}

static void sspi_new_local_address(struct mptcpd_interface const *i,
                                   struct sockaddr const *sa,
                                   struct mptcpd_pm *pm)
{
        l_info("NEW LOCAL ADDR");
        (void)i;
        (void)sa;
        (void)pm;
}

static void sspi_delete_local_address(struct mptcpd_interface const *i,
                                      struct sockaddr const *sa,
                                      struct mptcpd_pm *pm)
{
        l_info("NET ADDR removed");
        (void)i;
        (void)sa;
        (void)pm;
}

static struct mptcpd_plugin_ops const pm_ops = {
        .new_connection         = sspi_new_connection,
        .connection_established = sspi_connection_established,
        .connection_closed      = sspi_connection_closed,
        .new_address            = sspi_new_address,
        .address_removed        = sspi_address_removed,
        .new_subflow            = sspi_new_subflow,
        .subflow_closed         = sspi_subflow_closed,
        .subflow_priority       = sspi_subflow_priority,
        // network monitor event handler 
        .new_interface          = sspi_new_interface,       
        .update_interface       = sspi_update_interface,
        .delete_interface       = sspi_delete_interface,
        .new_local_address      = sspi_new_local_address,
        .delete_local_address   = sspi_delete_local_address
};

/*****************************************************************************************/

/*****************************************************************************************/ 

/**
 * @brief starts listeng thread. Listeng for upcoming Commands or data from NS-3
 * @param in mptcpd_pm path manager  
 */

static void* sspi_connect_pipe(void *in)
{
        if (in == NULL) EXIT_FAILURE; // path manager is required 
        //struct mptcpd_pm *const pm = (struct mptcpd_pm *)in;

        int fd;
        struct sspi_message msg;

        /* Creating the named file(FIFO) */
        unlink(SSPI_FIFO_PATH);
        mkfifo(SSPI_FIFO_PATH, 0666);

        /* non blocking syscall open() */
        fd = open(SSPI_FIFO_PATH, O_RDWR);
        
        if (fd < 0)
                exit(1); // check fd
        /* maybe it's better to use poll() for non bloking */
        ssize_t nb = 0; // num of bytes readed
        l_info("listening thead.. OK");
        while ((nb = read(fd, &msg, sizeof(struct sspi_message))) > 0)
        {
                /* now parsing msg data                 */
                /* read until receive stop command      */
                if (msg.type == SSPI_MSG_TYPE_CMD) {
                        if (sspi_msg_cmd_parse(
                                (struct sspi_cmd_message*) (&msg.data), in) < 0)
                                break;
                } else if (msg.type == SSPI_MSG_TYPE_DATA) {
                        if (sspi_msg_data_parse(
                                (struct sspi_data_message*) (&msg.data), in) < 0)
                                break;
                }
                // clean ?? 
                // memset(&msg, 0, sizeof(msg));
        }
        // close fd when nothing to read end exit the thread 
        //close(fd);
        l_info("Exit Reading thread");
        return EXIT_SUCCESS ; 
}

// called on plugin start 
static int sspi_init(struct mptcpd_pm *pm)
{
        /*
        /home/vad/mptcpd/build/src/mptcpd --plugin-dir=/home/vad/mptcpd/build/plugins/path_managers/.libs --path-manager=sspi --addr-flags=subflow
        */
    
        static char const name[] = "sspi";

        if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
                l_error("Failed to initialize "
                        "single-subflow-per-interface "
                        "path manager plugin.");

                return -1;
        }

        // @TODO Check if userspace PM type is enabled by sysctl: 
        // echo 0 > /proc/sys/net/mptcp/pm_type

        // Set & Check Limits setted
        sspi_set_limits(pm);
        if (mptcpd_kpm_get_limits(pm, sspi_get_limits_callback, NULL) != 0) {
                l_info("Unable to get limits IP addresses.");
        }
        
        sspi_subflows = l_queue_new();      // init lists of subflows  
        sspi_interfaces = l_queue_new();    // init lists of interfaces   
        
        // Get MPTCP interfaces info and save it to interfaces list 
        if (mptcpd_kpm_dump_addrs(pm, sspi_dump_addrs_callback,NULL,
                                dump_addrs_complete) !=0 ){
            l_info("Unable to dump MPTCP addresses.");
        }
        

        /**
         * create separate thread to listening ingomming data,
         * for example from NS3
         */
        pthread_t thread;
        if (pthread_create(&thread, NULL, sspi_connect_pipe, (void*) pm) != 0)
        {
                l_info("Plugin, can't create thread to receive incoming data");
                exit(EXIT_FAILURE);
        }
        
        l_info("MPTCP single-subflow-per-interface path manager initialized.");
        
        #ifdef USE_CORE
        l_info(" ! CORE IS USED !");
        #endif


        return 0;
}

// called on plugin end 
static void sspi_exit(struct mptcpd_pm *pm)
{
        l_info ("EXIT"); 
        (void) pm;
        // destroy dynamic lists  
        l_queue_destroy(sspi_interfaces, sspi_interface_info_destroy);
        l_queue_destroy(sspi_subflows, sspi_sf_destroy); 

        l_info("MPTCP single-subflow-per-interface path manager exited.");
}

MPTCPD_PLUGIN_DEFINE(sspi,
                     "Single-subflow-per-interface path manager",
                     MPTCPD_PLUGIN_PRIORITY_HIGH,
                     sspi_init,
                     sspi_exit)

/**
 * get NM
 * struct mptcpd_nm const *const nm = mptcpd_pm_get_nm(pm);
 *
 * mptcpd_nm_foreach_interface(nm,
                            sspi_send_addrs,
                            &connection_info);
 *
 */

// allocate mem e copy
// l_memdup(sa, sizeof(struct sockaddr_in))
// l_free(sa);

// l_malloc()  Allocate memmory
//  struct pm_ops_info *const info = l_malloc(sizeof(*info));
//  info->ops = ops;
//  info->user_data = user_data;

/**
 * ELL data struct (see ell/unit)
 *
 * l_hashmap
 *
 * l_queue
 *      // Create list of
 *      static struct l_queue *sspi_interfaces;
        sspi_interfaces = l_queue_new();
 *      l_queue_foreach(i->addrs, sspi_send_addr, info);

        l_queue_foreach_remove(sspi_interfaces,
                           sspi_remove_token,
                           L_UINT_TO_PTR(token))

 *      l_queue_remove(info->tokens, user_data);
 *      l_queue_remove_if()
 *      l_queue_insert(sspi_interfaces, info,
                            sspi_interface_info_compare,
                            NULL);
        l_queue_find(sspi_interfaces, sspi_index_match, &index);
        l_queue_destroy(info->tokens, NULL);
        l_queue_destroy(sspi_interfaces,
                        sspi_interface_info_destroy);
        l_free(info);
 *
 * l_uintset
 * l_ringbuf
 *
 * ELL Utils
 * l_getrandom
 *
 *
*/
// (void) pm;
// __attribute__ ((unused))

/*
  Local Variables:
  c-file-style: "linux"
  End:
*/
