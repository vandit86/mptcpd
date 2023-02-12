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

#define     SSPI_RSU_RADIUS         85     // RSU covarage area [m] 
#define     SSPI_RSS_THRESHOLD      -80    // dBm 
#define     SSPI_LINK_LOST_MS       1000   // check link lost time     
#define     SSPI_LINK_COST_MAX      50     // maximum cost of link usage     


/*  COMMANDS TYPES  */
/*  usage example : 
        (char) msg-type = cmd (01), 
        (char) write type = 3 (03), 
        (int)  value = 4 (00\00\00\04)
        \c     end output

    echo -en "\01\03\00\00\00\04\c" > /tmp/mptcp-ns3-fifo
*/    
enum sspi_commands{
    
    SSPI_CMD_UNDEFINED=0,   //    

    SSPI_CMD_TCPDUMP,       // 01 (ns-3)capture traffic during simulation    
    SSPI_CMD_CREATE_SF,     // 02 (manual) create new sf with the last added sf entry: echo -en "\01\02\00\00\00\00\c" > /tmp/mptcp-ns3-fifo 
    SSPI_CMD_BACKUP_ON,     // 03 (manual) BKP FLAG ON all subflows with l_id        
    SSPI_CMD_BACKUP_OFF,    // 04 (manual) BKP FLAG OFF all subflows with l_id (val)   
    SSPI_CMD_STOP_RV_MSG,   // 05 (mptcpd) stop receiving tread on mptcpd (used by main)
    SSPI_CMD_IPERF_START,   // 06 (ns-3) start iperf traf gen; VAL -> time is sec
    SSPI_CMD_REMOVE_SF,     // 07 (manual) remove sf l_id (?? nothing produce)
    
    SSPI_CMD_LAST           // last command value 

};

// different services types 
enum sspi_services{
        SSPI_SERVICE_MAX = 0,   // service garantee max throughput
        SSPI_SERVICE_LAST
}; 

/*  MESSAGE STRUCT  */
/**
 * @brief structure of message to be sent from ns-3 to mptcpd 
 * plugin 
 */
struct sspi_message
{
    unsigned char type;             // Msg type (CMD | DATA)
    char data [255];                // chould be >= data_message size 
};

// commands messages  
struct sspi_cmd_message
{
    unsigned char cmd;              // command from command list enum 
    int cmd_value;                  // command value (if any)
};


/**
 * @brief struct to represent phy characteristics of the channel 
 * https://gsm-repiteri.ru/chto-takoe-rssi-sinr-rsrp-rsrq-parametry-kachestva-signala   
 * 
 * @param signal RSS(wlan) or RSRP (lte)
 * @param noise 
 * @param pos_lat position of RSU (wlan) or eNb (lte)
 * @param is_connected is vehicle in coverage area of Network 
 */
struct sspi_phy_data
{
        double signal;      // signal   [dBm]
        double noise;       // noise    [dBm]
        double pos_lat;     // pos of rsu/eNb
        double pos_lon;     // 
        bool is_connected;  // [bool]   is connected to network
        double dweel_time;  // [s] estimated dwelling time (High value for LTE)
        double cost;        // cost value (max 50)
};

/**
 * @brief struct contain ego vehicle kinematic data 
 */
struct sspi_veh_data
{
        double speed;       // [m/s]
        double accel;       // [m^2/s]
        double pos_lat;     // [latitude]
        double pos_lon;     // [longitude]
        double angle;       // [º] see SUMO angle
}; 

/**
 * @brief struct contain per-flow connection information. 
 * Other flow metrics also could be used..
 * don't concider flow as valid if duration < 0 
 */
struct sspi_flow_data
{
        double rate;        // data rate    [Mbps]  
        double delay;       // delay        [ms]
        double jitter;      // jitter       [ms]
        double plr;         // loss rate    [%]
        int64_t duration;    // connection duration  [ms] ,   
}; 

/**
 * @brief data to be sent from ns-3 envirounment, that include ego vehicle data, 
 * channal phy characteristics and per flow metrics   
 */
struct sspi_data_message
{
        struct sspi_veh_data veh;               // vehicle data 
        struct sspi_phy_data phy_wlan;          // wlan channel  
        struct sspi_phy_data phy_lte;           // lte channel  
        struct sspi_flow_data flow_wlan ;       // flow on wlan path 
        struct sspi_flow_data flow_lte ;        // flow on lte path 
        uint64_t  timestamp_ms;                 // timestamp        [ms] 
}; 


// ::memcpy to serialize 

/*  MESSAGE TYPES*/

#endif // MPTCPD_NS3_H
