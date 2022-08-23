#if !defined(MPTCPD_NS3_H)
#define MPTCPD_NS3_H

// Set MPTCP Subflow Limits when plugin is loaded 
#define     SSPI_MAX_ADDR       2
#define     SSPI_MAX_SUBFLOWS   2

/*  FIFO NAME   */
#define SSPI_FIFO_PATH "/tmp/mptcp-ns3-fifo"

#define     SSPI_IFACE_LTE      1       // LTE endpoint ID
#define     SSPI_IFACE_WLAN     2       // 802.11 endpoint ID

#define     SSPI_MSG_TYPE_CMD       0x01   // command 
#define     SSPI_MSG_TYPE_DATA      0x02   // data from ns-3 

/*  COMMANDS TYPES  */
/*  usage example : 
        (char) msg-type = cmd (01), 
        (char) write type = 3 (03), 
        (int)  value = 4 (00\00\00\04)
        \c     end output

    echo -en "\01\03\00\00\00\04\c" > /tmp/mptcp-ns3-fifo
    echo -en "\02\01\c" > /tmp/mptcp-ns3-fifo  // set data ?? 
*/    
enum sspi_commands{
    
    SSPI_CMD_UNDEFINED=0,   //    

    SSPI_CMD_TCPDUMP,       // 01capture traffic during simulation    
    SSPI_CMD_DEL,           // (NOT) delete one path (endpoint id in value)
    SSPI_CMD_BACKUP_FLAG_ON,// (NOT) SET BACKUP FLAG ON mptcp ENDPOINT       
    SSPI_CMD_CLEAR_FLAGS,   // (NOT) Clear all flags on endpoint (val)   
    SSPI_CMD_STOP_RV_MSG,   // 05 stop receiving tread on mptcpd (used by main)
    SSPI_CMD_IPERF_START,   // 06 start iperf traf gen; VAL -> time is sec
    
    SSPI_CMD_LAST           // last command value 

}; 

/*  MESSAGE STRUCT  */
/**
 * @brief structure of message to be sent from ns-3 to mptcpd 
 * plugin 
 * todo : view padding, maybe put char type oin the end of struct
 * https://stackoverflow.com/questions/2748995/struct-memory-layout-in-c/2749096#:~:text=Struct%20members%20are%20stored%20in,of%20sizeof(T)%20bytes.
 * 
 */
struct sspi_message
{
    unsigned char type;           // Msg type (CMD | DATA)
    char data [255];  
};


// commands 
struct sspi_cmd_message
{
    unsigned char cmd;              // command from command list enum 
    int cmd_value;                  // command value (if any)
};

// data from ns-3 
struct sspi_data_message
{
    int rssi;           // rss value
}; 


// ::memcpy to serialize // https://stackoverflow.com/questions/16543519/serialization-of-struct

/*  MESSAGE TYPES*/

#endif // MPTCPD_NS3_H
