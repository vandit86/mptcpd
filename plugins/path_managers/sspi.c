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

#include "mptcpd/mptcp_ns3.h"
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
__attribute__ ((unused)) 
static void sspi_print_sock_addr (struct sockaddr const *addr){
          // // print local addr (4 bytes)    
        l_info ("addr = %02X:%02X:%02X:%02X",   addr->sa_data[2], 
                                                addr->sa_data[3],
                                                addr->sa_data[4],
                                                addr->sa_data[5]
                                                );
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

        if (in == NULL)
                return;
        
        struct mptcpd_pm *const pm = (struct mptcpd_pm *) in;
        int const result =
                mptcpd_kpm_set_limits(pm, _limits, L_ARRAY_SIZE(_limits));

        if (!result) {
                l_info("LIMITS CHANGED ADD_ADDR = %d , SUBFLOW = %d",
                       SSPI_MAX_ADDR,
                       SSPI_MAX_SUBFLOWS);
        }
}


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
        struct sspi_pass_info* pi = (struct sspi_pass_info *)in;
        struct mptcpd_pm *pm = (struct mptcpd_pm *)pi->pm;
        // struct sockaddr *laddr = (struct sockaddr *)&info->addr;
        //struct sockaddr *laddr = (struct sockaddr *)&info->addr;
        // (struct sockaddr const *) &info->addr;
        //struct sockaddr_in *laddr = (struct sockaddr_in *) &(info->addr);
        struct sockaddr const *laddr = mptcpd_addr_info_get_addr(info);
        // l_info("index = %d, id = %d, flags=%d",
        //        info->index, info->id, info->flags);
        // // set to backup
        
        // static mptcpd_flags_t const flags = 
        //                 (pi->data)? MPTCPD_ADDR_FLAG_BACKUP : 0 ;
        mptcpd_flags_t flags = (uint32_t) pi->data; 
        l_info("FLAG received = %d", (int) pi->data); 

        if (mptcpd_kpm_set_flags(pm, laddr, flags) != 0)
        {
                l_error("Unable to set flag %u", flags);
        }
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
                        l_info ("Add limit %u", l->limit); 
                } else if (l->type == MPTCPD_LIMIT_SUBFLOWS) {
                        l_info("Sub limit: %u", l->limit);
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

static void sspi_get_addr_callback(struct mptcpd_addr_info const *info,
                                        void *user_data)
{
        struct sspi_subflow* const data = (struct sspi_subflow* const) user_data; 
        l_info("token %u", data->token)  ; 
        
        data->laddr = mptcpd_addr_info_get_addr(info);
        
        sspi_print_sock_addr (data->laddr);
        l_info ("family l: %d ", data->laddr->sa_family);  
        
        sspi_print_sock_addr (data->raddr);
        l_info ("family r : %d", data->raddr->sa_family); 
               
        if (mptcpd_pm_add_subflow(data->pm,
                                data->token,
                                data->l_id,
                                data->r_id,
                                data->laddr,
                                data->raddr,
                                false) !=0)
        {
                l_error("Unable to establish subflow from id=: %d", data->l_id);
        }

        // dealocate memory  allocated with mptcpd_sockaddr_copy 
        l_free((void*)data->raddr); 
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
static int sspi_msg_pars (struct sspi_ns3_message* msg, void const *in){
                
       // l_info ("Msg type %i value %f", msg->type, (double)msg->value);
        l_info ("Msg type %i value %d", msg->type, (int)msg->value);

        if (in == NULL) return 0;
        struct mptcpd_pm *const pm = (struct mptcpd_pm *)in;
        
        // cmd from mptcpd to stop thread (called on Cntr+C)   
        if (msg->type == SSPI_CMD_END) return -1 ;

        /* will be used as copy on write on other processes*/
        char buf[128];

        /* Receive Init MSG : IPC connection OK 
           START tcpdump recording durring the simulation */
        if ( msg->type == SSPI_CMD_TCPDUMP){
              l_info("Start TCPDUMP");
              if (fork() == 0)
              {
                      sprintf(buf,
                              "tcpdump -G %d -W 1 -s 100 -w dump-0.pcap -i eth0",
                              msg->value);
                      l_info("%s", buf);
                      int status = system(buf);
                      exit(status);
              }
              if (fork() == 0)
              {
                      sprintf(buf,
                              "tcpdump -G %d -W 1 -s 100 -w dump-1.pcap -i eth1",
                              msg->value);
                      l_info("%s", buf);
                      int status = system(buf);
                      exit(status);
              }
        }
        // remove addr 
        else if (msg->type == SSPI_CMD_DEL ){
                const mptcpd_aid_t id = 2; 
                if (mptcpd_kpm_remove_addr(pm, id) != 0)
                        l_info("Unable to remove endpoint: %d", id);
                else  
                        l_info ("Endpoint %d Removed", id); 
        }

        // set Endpoint with (id = msg-value) with backup flag
        else if (msg->type == SSPI_CMD_BACKUP_FLAG_ON){
                // //  subflow ID to be changed 
                // mptcpd_aid_t id = (uint8_t) msg->value;  
                // // struct sspi_pass_info pi; 
                // pi.pm = (struct mptcpd_pm *)in; 
                // pi.data = (int) MPTCPD_ADDR_FLAG_BACKUP; // BACLUP flag
                
                // if (mptcpd_kpm_get_addr(pm, 
                //                         id,
                //                         sspi_set_flag_callback, 
                //                         (void *)&pi, 
                //                         sspi_empty_callback) != 0)
                // {
                //     l_error("Unable to get addr with id=: %d", id);
                // }

        //        if ( mptcpd_pm_remove_subflow(pm, sf2.token, sf2.laddr, 
        //                                 sf2.raddr) == 0)
        //         {
        //                 l_info("Backup OK");  
        //         }
        }

        // set Endpoint with (id = msg-value) with backup flag
        else if (msg->type == SSPI_CMD_CLEAR_FLAGS){
                //  subflow ID to be changed 
                mptcpd_aid_t id = (uint8_t) msg->value;  
                // struct sspi_pass_info pi; 
                pi.pm = (struct mptcpd_pm *)in; 
                pi.data = (int) 0;          // CLEAR all flags

                if (mptcpd_kpm_get_addr(pm, 
                                        id,
                                        sspi_set_flag_callback, 
                                        (void *)&pi,
                                        sspi_empty_callback) != 0)
                {
                    l_error("Unable to get addr with id=: %d", id);
                }
        }

        else if (msg->type == SSPI_CMD_WIFI_SNR){

                l_info ("SNR : %d", msg->value); 
                // if ( mptcpd_kpm_dump_addrs(pm, 
                //         sspi_set_flag_callback, (void*)in) !=0){
                //                 l_error ("Unable dump adrese"); 
                //         }
        }

        // stert generate traffic in separate process 
        else if (msg->type == SSPI_CMD_IPERF_START){
                
                if (fork() == 0){
                        sprintf(buf,
                                // "/home/vad/mptcp-tools/use_mptcp/use_mptcp.sh iperf -c 13.0.0.2 -e -i1 -n %d",
                                "/home/vad/mptcp-tools/use_mptcp/use_mptcp.sh iperf -c 13.0.0.2 -e -i1 -t %d",
                                msg->value);
                        l_info("%s",buf); 
                        int status = system(buf);
                        // maybe should try with execl () instead of system()
                        // execl("/path/to/foo", "foo", "arg1", "arg2", "arg3", 0);
                        exit(status);  
                }

        }  
        else{
                // just inform user, continue to reading 
                l_info("Uknown ns3 message : %d", (int)msg->type);
        }
      
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
        struct sspi_ns3_message msg;

        /* Creating the named file(FIFO) */
        unlink(SSPI_FIFO_PATH);
        mkfifo(SSPI_FIFO_PATH, 0666);

        /* non blocking syscall open() */
        fd = open(SSPI_FIFO_PATH, O_RDWR);

        if (fd < 0)
                exit(1); // check fd

        /* maybe it's better to use poll() for non bloking */
        ssize_t nb = 0; // num of bytes readed
        l_info("listening thead..");
        while ((nb = read(fd, &msg, sizeof(msg))) > 0)
        {
                /* now parsing msg data                 */
                /* read until receive stop command      */
                l_info("Received: %lu bytes \n", nb);
                
                // receive "end" command
                if (sspi_msg_pars(&msg, in) < 0)
                        break;
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

static void sspi_connection_established(mptcpd_token_t token,
                                        struct sockaddr const *laddr,
                                        struct sockaddr const *raddr,
                                        bool server_side, 
                                        struct mptcpd_pm *pm)
{
        l_info("CONNECTION ESTABLISHED: token = %u, server_side = %d ",
               token,
               server_side);

        (void) server_side;  
        (void) token;
        (void) laddr;
        (void) raddr;
        (void) pm;

        /**
         * @todo Implement this function.
         */
       // l_warn("%s is unimplemented.", __func__); 
}

static void sspi_connection_closed(mptcpd_token_t token,
                                   struct mptcpd_pm *pm)
{
        l_info ("CONNECTION CLOSED"); 
        (void) pm;
        (void) token; 

        /*
          Remove all sspi_interface_info objects associated with the
          given connection token.
        */
      
}

static void sspi_new_address(mptcpd_token_t token,
                             mptcpd_aid_t id,
                             struct sockaddr const *addr,
                             struct mptcpd_pm *pm)
{
        l_info ("NEW ADD_ADDR: token = %u , id = %u", token, id);
        sspi_print_sock_addr (addr);
        l_info ("new addr family r : %d", addr->sa_family);

        mptcpd_aid_t m_id = 2; // HARDCODED
        struct sockaddr *const sa = mptcpd_sockaddr_copy(addr);
        
        struct sspi_subflow* const data = &sf2; 
        data->pm = pm ; 
        data->token = token; 
        data->l_id = m_id; 
        data->r_id = id; 
        data->raddr = sa;
        data->laddr = NULL;     // we need to find out this addr to create sf 

        mptcpd_kpm_get_addr(pm, m_id, sspi_get_addr_callback, data, NULL);  

       

        (void) token;
        (void) id;
        (void) addr;
        (void) pm;

        /*
          The sspi plugin doesn't do anything with newly advertised
          addresses.
        */
    
}

static void sspi_address_removed(mptcpd_token_t token,
                                 mptcpd_aid_t id,
                                 struct mptcpd_pm *pm)
{
        l_info ("ADDR REMOVED");
        (void) token;
        (void) id;
        (void) pm;

        /*
          The sspi plugin doesn't do anything with addresses that are
          no longer advertised.
        */
}

static void sspi_new_subflow(mptcpd_token_t token,
                             struct sockaddr const *laddr,
                             struct sockaddr const *raddr,
                             bool backup,
                             struct mptcpd_pm *pm)
{
        l_info ("NEW SUBFLOW local <--> remote, backup %u, token: %u ", 
                                                backup, token);
        //sspi_print_sock_addr (laddr); 
        //sspi_print_sock_addr (raddr);
        
        (void) token;
        (void) laddr; 
        (void) raddr; 
        (void) backup; 
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
        l_info ("UPDATE interface flags");
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
        //l_warn ("INIT PM");

        static char const name[] = "sspi";

        if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
                l_error("Failed to initialize "
                        "single-subflow-per-interface "
                        "path manager plugin.");

                return -1;
        }

        /*
        /home/vad/mptcpd/build/src/mptcpd --plugin-dir=/home/vad/mptcpd/build/plugins/path_managers/.libs --path-manager=sspi --addr-flags=subflow
        */
        l_info("MPTCP single-subflow-per-interface "
               "path manager initialized.");

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
        //l_memdup(sa, sizeof(struct sockaddr_in))   
        //l_free(sa); 

        //l_malloc()  Allocate memmory 
        // struct pm_ops_info *const info = l_malloc(sizeof(*info));
        // info->ops = ops;
        // info->user_data = user_data;

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

        sspi_set_limits(pm);
        
        if (mptcpd_kpm_get_limits(pm, sspi_get_limits_callback,
                                  NULL) != 0)
            l_info("Unable to get limits IP addresses.");
        
        
        /**
         * create separate thread to listening ingomming data,
         * for example from NS3
         */

        pthread_t thread;
        int status;
        status = pthread_create(&thread, NULL, sspi_connect_pipe, 
                (void*) pm);
        if (status != 0)
        {
                l_info("Plugin, can't create thread to receive incoming data");
                exit(EXIT_FAILURE);
        }

        return 0;
}

static void sspi_exit(struct mptcpd_pm *pm)
{
        l_info ("EXIT"); 
        (void) pm;

        l_info("MPTCP single-subflow-per-interface path manager exited.");
}

MPTCPD_PLUGIN_DEFINE(sspi,
                     "Single-subflow-per-interface path manager",
                     MPTCPD_PLUGIN_PRIORITY_DEFAULT,
                     sspi_init,
                     sspi_exit)


/*
  Local Variables:
  c-file-style: "linux"
  End:
*/
