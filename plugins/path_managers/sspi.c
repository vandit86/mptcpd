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

// #include <mptcpd/private/path_manager.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
//#include <conio.h>

#include <mptcpd/addr_info.h>

#include <mptcpd/plugin.h>

// requered for pipe fifo
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
#include <mptcpd/private/sockaddr.h>


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
        mptcpd_aid_t l_id;              // local address id  
        mptcpd_aid_t r_id;              // remote address id (received from peer)
        struct sockaddr const *laddr;   // local IP addr
        struct sockaddr const *raddr;   // remote IP addr 
        bool backup;                    // is subflow backup priority flag 
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



/**
 * @struct sspi_new_subflow_info
 * @brief Pass subflow data and pm, used in callback functions
 * 
 * This is a convenience structure for the purpose of making it easy
 * to pass operation arguments through a single variable.
 */
struct sspi_new_subflow_info
{
        /// MPTCP subflow info (may be incomplete)
        struct sspi_subflow_info *const sf;

        /// Pointer to path manager.
        struct mptcpd_pm *const pm;
};

/*
*******************************************************************
*      Additional functions
* ******************************************************************
*/

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
static void sspi_subflows_destroy(void *p)
{
        if (p == NULL) return;
        struct sspi_subflow_info *const info = p;
        l_free(info);
}


// show mptcp interfaces id and index (debug func)
static void sspi_foreach_show(void *data, void *user_data)
{
    (void) user_data; 
    struct sspi_subflow_info const *const sf = data;

    
    l_info ("Subflow: %u backup %u", sf->token, sf->backup) ;
    sspi_sock_addr_print(sf->laddr);
    sspi_sock_addr_print(sf->raddr);
}

/**
 * Create @c sspi_subflow_info struct and save new subflow into subflows list
 * @param id mptcp endpoint id could be SSPI_IFACE_WLAN or SSPI_IFACE_LTE 
 * (see mptcp_ns3.h).  ID is nedded to identify network 
 * assuming initial connection maded through LTE subflow
 * assuming additional connection on WLAN network 
 * all new sf's came without backup flag, i.e. backup = false 
 */
static void sspi_subflow_add( mptcpd_token_t token,
                                struct sockaddr const *laddr,
                                struct sockaddr const *raddr, 
                                mptcpd_aid_t id)
{
        // struct sspi_subflow_info *const info = l_malloc(sizeof(*info));
        struct sspi_subflow_info *const info =
                l_malloc(sizeof(struct sspi_subflow_info));

        info->l_id = info->r_id = id;
        info->token             = token;
        info->backup            = false;
        info->laddr             = mptcpd_sockaddr_copy(laddr);
        info->raddr             = mptcpd_sockaddr_copy(raddr);

        // push new subflow into the list
        l_queue_push_tail(sspi_subflows, (void *) info);

        l_info ("Print SF list : "); 
        l_queue_foreach (sspi_subflows, sspi_foreach_show, NULL); 
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
bool sspi_subflow_remove(void *data, void *user_data)
{
        assert(data);
        assert(user_data);

        struct sspi_subflow_info *const info = data;
        return info->token == L_PTR_TO_UINT(user_data); 
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

/********************************************************************/
/********************************************************************/


/**
 *      Get address, SET FALG callback, 
 *      USED TO SET FLAG ON MPTCP endpoint 
 *      Can be used during mptcp session 
 *      for example :  echo -en "\02\0\0\0\01\0\0\0\c" > /tmp/mptcp-ns3-fifo
 *      will set endpoint (id = 2) with BAKUP flag 
*/
__attribute__((unused)) 
static void sspi_set_flag_callback(struct mptcpd_addr_info  const *info,
                                                           void *in)
{
        (void) info; 
        (void) in; 
        // struct sspi_pass_info* pi = (struct sspi_pass_info *)in;
        // struct mptcpd_pm *pm = (struct mptcpd_pm *)pi->pm;
        // // struct sockaddr *laddr = (struct sockaddr *)&info->addr;
        // //struct sockaddr *laddr = (struct sockaddr *)&info->addr;
        // // (struct sockaddr const *) &info->addr;
        // //struct sockaddr_in *laddr = (struct sockaddr_in *) &(info->addr);
        // struct sockaddr const *laddr = mptcpd_addr_info_get_addr(info);
        // // l_info("index = %d, id = %d, flags=%d",
        // //        info->index, info->id, info->flags);
        // // // set to backup
        
        // // static mptcpd_flags_t const flags = 
        // //                 (pi->data)? MPTCPD_ADDR_FLAG_BACKUP : 0 ;
        // mptcpd_flags_t flags = (uint32_t) pi->data; 
        // l_info("FLAG received = %d", (int) pi->data); 

        // if (mptcpd_kpm_set_flags(pm, laddr, flags) != 0)
        // {
        //         l_error("Unable to set flag %u", flags);
        // }
}

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

        for (struct mptcpd_limit const *l = limits;
             l != limits + len; ++l) {
                if (l->type == MPTCPD_LIMIT_RCV_ADD_ADDRS) {
                        l_info ("ADD_ADDR LIMIT %u", l->limit); 
                } else if (l->type == MPTCPD_LIMIT_SUBFLOWS) {
                        l_info("SUBFLOW LIMIT: %u", l->limit);
                } else {
                        l_error("Unexpected MPTCP limit type.");
                }
        }
}

/****************************************************************/
/**
 * @struct sspi_nm_callback_data
 *
 * @brief Type used to return index associated with local address.
 *
 * @see @c mptcpd_nm_callback
 */
struct sspi_nm_callback_data
{
        /// Local address information.        (IN)
        struct sockaddr const* const addr;

        /// Network interface (link) index.   (OUT)
        int index;
};

__attribute__((unused)) 
static void sspi_get_addr_callback(struct mptcpd_addr_info const *info,
                                        void *user_data)
{
        (void) info; 
        (void) user_data; 
        // struct sspi_subflow* const data = (struct sspi_subflow* const) user_data; 
        // l_info("token %u", data->token)  ; 
        
        // data->laddr = mptcpd_addr_info_get_addr(info);
        
        // sspi_print_sock_addr (data->laddr);
        // l_info ("family l: %d ", data->laddr->sa_family);  
        
        // sspi_print_sock_addr (data->raddr);
        // l_info ("family r : %d", data->raddr->sa_family); 
               
        // if (mptcpd_pm_add_subflow(data->pm,
        //                         data->token,
        //                         data->l_id,
        //                         data->r_id,
        //                         data->laddr,
        //                         data->raddr,
        //                         false) !=0)
        // {
        //         l_error("Unable to establish subflow from id=: %d", data->l_id);
        // }

        // // dealocate memory  allocated with mptcpd_sockaddr_copy 
        // l_free((void*)data->raddr); 
}

/*******************************************************************/

/**
 * @brief parsing incoming msg from ns-3 
 * 
 * @param msg message to be parsed 
 * @param in pointer to struct mptcpd_pm *const, need cast from void
 * 
 * @return -1 if receives "end" command from mptcpd main therad.. 
 *              0 othervise   
 */
static int 
sspi_msg_cmd_parse (struct sspi_cmd_message* msg){

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
							"-w", "dump.pcap", (char *)0); 
              }
            //   if (fork() == 0)
            //   {
            //         sprintf(buf, "timeout --signal=KILL %d tcpdump -s 100 -w dump-1.pcap -i eth1",
            //                 msg->cmd_value);
            //         l_info("%s", buf);
            //         int status = system(buf);
            //         exit(status);
            //   }
        }

        // /**
        //  * echo -en "\02\0\0\0\01\0\0\0\c" > /tmp/mptcp-ns3-fifo
        //  * will set endpoint (id = 2) with BAKUP flag
        //  */
        // else if (msg->type == SSPI_CMD_BACKUP_FLAG_ON) {
        //         //  subflow ID to be changed
        //         //mptcpd_aid_t id = (uint8_t) msg->value;

        //         struct sspi_subflow_info *info =
        //                 l_queue_peek_tail(sspi_subflows);

        //         if (mptcpd_pm_set_backup(pm,
        //                             info->token,
        //                             info->laddr,
        //                             info->raddr,
        //                             true) !=0)
        //         {
        //             l_error ("Can't set backup on subflow in %u",
        //             info->token);
        //         }

        // }

        // // set Endpoint with (id = msg-value) with backup flag
        // else if (msg->type == SSPI_CMD_CLEAR_FLAGS) {
        //         //  subflow ID to be changed
        //         // mptcpd_aid_t id = (uint8_t) msg->value;
        //         // struct sspi_pass_info pi;
        //         // pi.pm = (struct mptcpd_pm *)in;
        //         // pi.data = (int) 0;          // CLEAR all flags

        //         // if (mptcpd_kpm_get_addr(pm,
        //         //                         id,
        //         //                         sspi_set_flag_callback,
        //         //                         (void *)&pi,
        //         //                         sspi_empty_callback) != 0)
        //         // {
        //         //     l_error("Unable to get addr with id=: %d", id);
        //         // }
        // }

        // stert generate traffic in separate process
        else if (msg->cmd == SSPI_CMD_IPERF_START) {
            if (fork() == 0) {
                char buf[64];
                // maybe should try with execl () instead of system
				sprintf(buf,"iperf -c 13.0.0.2 -e -i1 -t %d", msg->cmd_value); 
                l_info("%s", buf);
				execl ("/home/vad/mptcp-tools/use_mptcp/use_mptcp.sh", 
						"use_mptcp.sh", 
						buf, (char *)0);
                }

        } else {
                // just inform user, continue to reading 
                l_info("Uknown CMD msg : %d", msg->cmd);
        }

        return EXIT_SUCCESS; 
}

static int 
spi_msg_data_parse (struct sspi_data_message* msg){
        l_info("rssi %u", msg->rssi);
        return EXIT_SUCCESS; 
} 

/**
 * @brief starts listeng thread. Listeng for upcoming commands from NS-3
 *  
 * @param in mptcpd_pm path manager  
 */

static void* sspi_connect_pipe(void *in)
{
        if (in == NULL) EXIT_FAILURE; // path manager
        
        // struct mptcpd_pm *const pm = (struct mptcpd_pm *)in;

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
                l_info("Received: %lu bytes \n", nb);
                l_info("msg type : %d", msg.type);

                if (msg.type == SSPI_MSG_TYPE_CMD) {
                        if (sspi_msg_cmd_parse(
                                (struct sspi_cmd_message*) (&msg.data)) < 0)
                                break;
                } else if (msg.type == SSPI_MSG_TYPE_DATA) {
                        if (spi_msg_data_parse(
                                (struct sspi_data_message*) (&msg.data)) < 0)
                                break;
                }

                // clean ?? 
                // memset(&msg, 0, sizeof(msg));
                // receive "end" command
                // if (sspi_msg_pars(&msg, in) < 0)
                //         break;
        }
        // close fd when nothing to read end exit the thread 
        //close(fd);
        l_info("Exit Reading thread");
        return EXIT_SUCCESS ; 
}


// ----------------------------------------------------------------
//                     Mptcpd Plugin Operations
// ----------------------------------------------------------------
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
        l_info("CONNECTION ESTABLISHED: token = %u", token);
        
        // create initial sf_info 
        sspi_subflow_add (token,laddr,raddr,SSPI_IFACE_LTE); 

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
                                   sspi_subflow_remove,
                                   L_UINT_TO_PTR(token)) == 0)
                l_error("Untracked connection closed.");

        (void) pm;      
}

/**
 * We receive ADD_ADDR from pear : 
 * Try to establish new subflow on WLAN iface using the data provided by peer.
 */
static void sspi_new_address(mptcpd_token_t token,
                             mptcpd_aid_t id,
                             struct sockaddr const *addr,
                             struct mptcpd_pm *pm)
{
        l_info ("NEW ADD_ADDR: token = %u , remote id = %u", token, id);
        
        // find wlan interface info 
        mptcpd_aid_t id_wlan = SSPI_IFACE_WLAN; 
        struct mptcpd_addr_info *info = l_queue_find( sspi_interfaces, 
                                            sspi_interface_id_match, 
                                            &id_wlan);
        assert(info);
        
        // find local addr of wlan interface 
        struct sockaddr const *l_addr = mptcpd_addr_info_get_addr(info); 
        assert(l_addr); 
        
        // struct sockaddr *const raddr = mptcpd_sockaddr_copy(addr);

        // establish new subflow connection with wlan network 
        if (mptcpd_pm_add_subflow(pm, token, SSPI_IFACE_WLAN,
                                  id, l_addr, addr, false) != 0) {
                l_error("Unable to establish subflow for token  %u", token);
        }
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
        // create sf info and add to list 
        sspi_subflow_add (token, laddr, raddr, SSPI_IFACE_WLAN); 
        (void) pm;
        (void) backup; 
          
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
        l_info ("SUBFLOW PRIORITY");
        (void) token;
        (void) laddr;
        (void) raddr;
        (void) backup;
        (void) pm;
        
        /*
            The sspi plugin doesn't do anything with changes in subflow
            priority.
        */
}

/**
 *      network monitor event handlers 
*/

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

        return 0;
}

static void sspi_exit(struct mptcpd_pm *pm)
{
        l_info ("EXIT"); 
        (void) pm;

        // destroy dynamic lists  
        l_queue_destroy(sspi_interfaces, sspi_interface_info_destroy);
        l_queue_destroy(sspi_subflows, sspi_subflows_destroy); 

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
