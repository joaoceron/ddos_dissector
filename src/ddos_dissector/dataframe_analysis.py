import math
from datetime import datetime
import numpy as np
import pandas as pd
pd.set_option('display.max_colwidth', -1)
pd.set_option('display.max_columns', 100)
import hashlib
from ddos_dissector.exceptions.UnsupportedFileTypeError import UnsupportedFileTypeError
from ddos_dissector.portnumber2name import portnumber2name
from ddos_dissector.protocolnumber2name import protocolnumber2name
from ddos_dissector.tcpflagletters2names import tcpflagletters2names

from datetime import datetime


def analyze_dataframe(df, dst_ip, file_type):
    """
    Analyze a dataframe, and return the fingerprints
    :param df: The Pandas dataframe
    :param dst_ip: The destination IP (if entered) or False
    :param file_type: The file type string
    :return: The fingerprints
    :raises UnsupportedFileTypeError: If the file type is not supported
    """
    if file_type == "pcap" or file_type == "pcapng":
        return analyze_pcap_dataframe(df, dst_ip)
    elif file_type == "nfdump":
        return analyze_nfdump_dataframe(df, dst_ip)
    else:
        raise UnsupportedFileTypeError("The file type " + file_type + " is not supported.")

def analyze_pcap_dataframe(df, dst_ip):
    total_packets = len(df)
    fingerprints = []
    attack_vector = {}
    attack_vector['file_type'] = 'pcap'
    #df_attackvectors = []
    attack_vector_labels = []
    attack_vector_source_ips = []
    counter = 1
    threshold_1to1 = 0.6
    threshold_min_srcIPS = 3
    DNS_sourceIPS = []
    DNS_sourceIPS_unique = 0


    
    print('STEP 3.1: Discovering Top 1 Destination IP... ')
    if dst_ip:
        top1_dst_ip = dst_ip
        print("\nOUTPUT 3.1:", top1_dst_ip)
    else:
        dst_ip_distribution = df['_ws.col.Destination'].value_counts().head()
        print("\nDISTRIBUTION OF TOP DESTINATION IPS: \n", dst_ip_distribution)
        top1_dst_ip = dst_ip_distribution.keys()[0]
        print("\nOUTPUT 3.1:", top1_dst_ip)
    print('********************************************************************************************')

    df_remaining = df[df['_ws.col.Destination'] == top1_dst_ip]

    ## a variable is needed to save the data, as df_remaining will be changed in the while-loop to make the code clearer
    df_saved = df_remaining

    while len(df_remaining) > 1 :
        
        # Analyse the distribution of IP protocols (and defining the top1)
        #STEP 3.2: Discovering Top 1 IP Protocol
        print('STEP 3.2: Discovering Top 1 IP Protocol...')

        protocol_distribution = df_remaining['ip.proto'].value_counts().head()
        print("\nDISTRIBUTION OF TOP IP PROTOCOLS: \n",protocol_distribution)
        top1_protocol = protocol_distribution.keys()[0]
        attack_vector['ip_protocol'] = top1_protocol
        print("\nOUTPUT 3.2:", top1_protocol)

        #adding the findings to the attack_vector_filter 
        attack_vector_filter_string = ""
        attack_vector_filter_string = "(df_saved['ip.proto'] == '" + str(top1_protocol) + "')"

        df_remaining = df_remaining[df_remaining['ip.proto'] == top1_protocol]

        # Calculating the number of packets after the first filter (for calculating the percentages bellow)
        total_packets_filtered = len(df_remaining)

        print('********************************************************************************************')
        if (top1_protocol != '1'): #| (top1_protocol == '6'):
            # Analyse the distribution of SOURCE ports AND define the top1

            print('STEP 3.3: Discovering Top 1 Port')
            port_source_distribution = df_remaining['srcport'].value_counts(normalize=True).head()
            print("\nDISTRIBUTION OF SOURCE PORT: \n", port_source_distribution)
            top1_source_port = math.floor(port_source_distribution.keys()[0])

            # Analyse the distribution of DESTINATION ports AND define the top1
            port_destination_distribution = df_remaining['dstport'].value_counts(normalize=True).head()
            print("\nDISTRIBUTION OF TOP DESTINATION PORTS: \n",port_destination_distribution)
            top1_destination_port = math.floor(port_destination_distribution.keys()[0])

            # Check which port type (source or destination) AND number had most occurrences
            if port_source_distribution.iloc[0] > port_destination_distribution.iloc[0]:
                print("\nOUTPUT 3.3: The highest frequency is SOURCE port: ", top1_source_port)
                df_remaining = df_remaining[df_remaining['srcport'] == top1_source_port]
                attack_vector_filter_string +="&(df_saved['srcport'] == " + str(top1_source_port) + ")"
                #filter_top_port = "df_remaining['srcport']==" + str(top1_source_port
                print('********************************************************************************************')
                print('STEP 3.4: Analysing top 1 DESTINATION port frequency and THRESHOLD')
                print('THRESHOLD =', threshold_1to1)

                if (port_destination_distribution.iloc[0] > threshold_1to1):
                    df_remaining = df_remaining[df_remaining['dstport'] == top1_destination_port]
                    attack_vector_filter_string +="&(df_saved['dstport'] == " + str(top1_destination_port) + ")"
                    print('\nOUTPUT 3.4: DESTINATION port',top1_destination_port, 'is considered as part of the attack vector.' )
                else:
                    print('\nOUTPUT 3.4: DESTINATION port',top1_destination_port, 'is NOT considered as part of the attack vector.' )

            else:
                print("\nOUTPUT 3.3: The highest frequency is DESTINATION port: ", top1_destination_port)
                df_remaining = df_remaining[df_remaining['dstport'] == top1_destination_port]
                attack_vector_filter_string +="&(df_saved['dstport'] == " + str(top1_destination_port) + ")"

                print('********************************************************************************************')
                print('STEP 3.4: Analysing top 1 SOURCE port frequency and THRESHOLD')
                print('THRESHOLD =', threshold_1to1)
                print(port_source_distribution.iloc[0])
                if (port_source_distribution.iloc[0] > threshold_1to1):
                    df_remaining = df_remaining[df_remaining['srcport'] == top1_source_port]
                    attack_vector_filter_string +="&(df_saved['srcport'] == " + str(top1_source_port) + ")"
                    print('\nOUTPUT 3.4: SOURCE port',top1_source_port, 'is considered as part of the attack vector.' )
                else:
                    print('\nOUTPUT 3.4: SOURCE port',top1_source_port, 'is NOT considered as part of the attack vector.' )

            print('********************************************************************************************')
            print("STEP 3.5: Analysing the Protocol for idenfying extra information\n")

            #Case UDP
            if (top1_protocol == '17'):

                #set service port to 0
                attack_vector['service'] = "NA"

                #DNS
                if (top1_source_port == 53) | (top1_destination_port == 53) :
                    if len(df_remaining['dns.qry.name']) > 0:
                        dns_query_distribution = df_remaining['dns.qry.name'].value_counts(normalize=True).head()
                        print("DISTRIBUTION OF TOP DNS QUERIES:\n",dns_query_distribution)
                        top1_dns_query = dns_query_distribution.keys()[0]
                        filter_dns_query = "df_remaining['dns.qry.name']=='" + str(top1_dns_query) + "'"
                        if (top1_dns_query != 0):
                            attack_vector_filter_string += "&(df_saved['dns.qry.name']=='" + str(top1_dns_query) + "')"
                            df_remaining = df_remaining[df_remaining['dns.qry.name'] == top1_dns_query]

                            dns_type_distribution = df_remaining['dns.qry.type'].value_counts().head()
                            print("\nDISTRIBUTION OF TOP DNS TYPES: \n ",dns_type_distribution)
                            top1_dns_type = dns_type_distribution.keys()[0]

                            attack_vector['service'] = "DNS"
                            print("attack_vector['service']")
                
                            attack_vector['additional'] = {
                            'dns_query': top1_dns_query,
                            'dns_type': top1_dns_type
                            }
                            print("\nOUTPUT 3.5: DNS QUERY TYPE:",top1_dns_type)
                            print('********************************************************************************************')

                #NTP
                elif (top1_source_port == 123) | (top1_destination_port == 123) :
                    if len(df_remaining['ntp.priv.reqcode']) > 0:
                        ntp_mode_distribution = df_remaining['ntp.priv.reqcode'].value_counts(normalize=True).head()
                        print("DISTRIBUTION OF TOP NTP RESPONSE:\n",ntp_mode_distribution)
                        top1_ntp_response = math.floor(ntp_mode_distribution.keys()[0])
                        attack_vector_filter_string += "&(df_saved['ntp.priv.reqcode'] == " + str(top1_ntp_response) + ")"

                        df_remaining = df_remaining[df_remaining['ntp.priv.reqcode'] == top1_ntp_response]
                        attack_vector['additional'] = {'ntp_reqcode': top1_ntp_response}
                        attack_vector['service'] = "NTP"
                        print("\nOUTPUT 3.5: NTP REQCODE:",top1_ntp_response)
                        print('********************************************************************************************')

                #Fragmentation
                elif (top1_source_port == 0)| (top1_destination_port == 0) :
                    print("\nOUTPUT 3.5: Fragmentation")
                    ip_flag_mf_distribution = df_remaining['ip.flags.mf'].value_counts(normalize=True).head()
                    print("DISTRIBUTION OF TOP IP FLAG MF\n", ip_flag_mf_distribution)
                    top1_ip_flag_mf = ip_flag_mf_distribution.keys()[0]

                    ip_flag_offset_distribution = df_remaining['ip.frag_offset'].value_counts(normalize=True).head()
                    print("DISTRIBUTION OF TOP IP FLAG OFFSET\n", ip_flag_offset_distribution)
                    top1_ip_flag_offset = ip_flag_offset_distribution.keys()[0]

                    if ip_flag_mf_distribution.iloc[0] == 1:
                        if ip_flag_offset_distribution.iloc[0] > 1:
                            attack_vector['additional'] = {'ip_flag_mf':top1_ip_flag_mf, 'ip_flag_offset': top1_ip_flag_offset}
                        else:
                            attack_vector['additional'] = {'ip_flag_mf':top1_ip_flag_mf}
                    elif ip_flag_offset_distribution.iloc[0] > 1:
                        attack_vector['additional'] = {'ip_flag_offset': top1_ip_flag_offset}
                    else:
                        attack_vector['additional'] = "Fragmentation"
                    
                    print('********************************************************************************************')



                else:
                    print("\nOUTPUT 3.5: There is NO extra information about UDP port",top1_source_port, "in the network flow.")
                    print('********************************************************************************************')


            #Case TCP
            if (top1_protocol == '6'):
                if 'tcp.flags.str' in df_remaining.columns:
                    tcp_flag_distribution =  df_remaining[df_remaining['ip.proto'] == '6']['tcp.flags.str'].value_counts().head()
                    print("DISTRIBUTION OF TOP TCP FLAGS: \n",tcp_flag_distribution)
                    top1_tcp_flag = tcp_flag_distribution.keys()[0]
                    print("\nOUTPUT 3.5: TCP flag:", top1_tcp_flag)
                    attack_vector_filter_string += "&(df_saved['tcp.flags.str'] == '" + str(tcp_flag_distribution.keys()[0]) + "')"
                    df_remaining = df_remaining[df_remaining['tcp.flags.str'] == tcp_flag_distribution.keys()[0]]
                    attack_vector['additional'] = {'tcp_flag': tcp_flag_distribution.keys()[0]}
                    print('********************************************************************************************')

        else:
            if (top1_protocol == '1'):
                print("STEP 3.5: Analysing the Protocol for idenfying extra information...")
                ICMP_port_distribution = df_remaining['icmp.type'].value_counts(normalize=True).head()
                print("\nDISTRIBUTION OF ICMP ports: \n",ICMP_port_distribution)
                top1_icmp_type = ICMP_port_distribution.keys()[0]

                ICMP_code_distribution = df_remaining['icmp.code'].value_counts(normalize=True).head()
                print("\nDISTRIBUTION OF ICMP code: \n",ICMP_code_distribution)
                top1_icmp_code = ICMP_code_distribution.keys()[0]
            
                if (ICMP_code_distribution.iloc[0] == 1):
                    attack_vector['additional'] = {'icmp.type': top1_icmp_type, 'icmp_code' : top1_icmp_code} 
                else: 
                    attack_vector['additional'] = {'icmp.type': top1_icmp_type}

                attack_vector_filter_string += "&(df_saved['icmp.type'] == '" + str(top1_icmp_type) + "')"
                df_remaining = df_remaining[df_remaining['icmp.type'] == top1_icmp_type]
                print("\nOUTPUT 3.5: ICMP type",top1_icmp_type,"is part of the attack")
                print('********************************************************************************************')

        attack_vector_labels.append(attack_vector_filter_string.replace("df_saved", ""))

        #df_attack_vector_current = df_saved[eval(attack_vector_filter_string)]

        src_ips_attack_vector_current = df_remaining['_ws.col.Source'].unique()
        src_ips = []

        # Determine packet length avg, packet length deviation, ttl avg, ttl deviation, number of packets.
        for ip in src_ips_attack_vector_current:
            #df_remaining: pd.DataFrame = df_remaining
            #df_ip = df_remaining.loc[df_remaining["_ws.col.Source"] == ip]
            df_ip = df_remaining[df_remaining["_ws.col.Source"] == ip]
            packets_sent = df_ip.shape[0]
            avg_packet_length = df_ip["frame.len"].sum() / packets_sent
            deviation_packet_length = df_ip["frame.len"].max() - df_ip["frame.len"].min()
            #df_ip["ip.ttl"] = df_ip["ip.ttl"].apply(lambda x: int(x))
            #avg_ttl = int(df_ip["ip.ttl"].sum()) / packets_sent
            #deviation_ttl = int(df_ip["ip.ttl"].max()) - int(df_ip["ip.ttl"].min())
            src_ips.append({
                "ip": ip,
                "pkt_count": packets_sent,
                "avg_pkt": avg_packet_length,
                "dev_pkt": deviation_packet_length,
            #    "avg_ttl": avg_ttl,
            #    "dev_ttl": deviation_ttl
            })


        # If the number of source IPs involved in this potential attack vector is 1, then it is NOT a DDoS!
        if len(src_ips_attack_vector_current) < threshold_min_srcIPS:
            print("DISCARTED ATTACK VECTOR " + str(counter) + ": " + str(attack_vector_filter_string).replace("df_saved", ""))
            print("  - Packets:" + str(len(df_remaining)))
            print("  - #Src_IPs:" + str(len(src_ips_attack_vector_current)))
            print("\nSTOP ANALYSIS; THERE IS ONLY ONE SOURCE IP RELATED TO THIS ATTACK VECTOR!")
            print("################################################################################")
            print("################################################################################\n")
            break

        ###################################################
        #FROM HERE WE ANALYSE THE REMAINING SRC_IPS AND THE OVERALL STATISTICS
        ###################################################

        # For later comparing the list of IPs
        attack_vector_source_ips.append(src_ips_attack_vector_current)

        attack_vector['src_ips'] = src_ips_attack_vector_current.tolist()
        attack_vector['src_ips2'] = src_ips
        attack_vector['total_src_ips'] = len(attack_vector['src_ips'])

        #DNS_sourceIPS = []
        if (top1_source_port == 53) | (top1_destination_port == 53) :
            DNS_sourceIPS += src_ips_attack_vector_current.tolist()



        if str(df_remaining['srcport'].iloc[0]) != 'nan':
            attack_vector['src_ports'] = [int(x) for x in df_remaining['srcport'].unique().tolist() if
                                          not math.isnan(x)]
        else:
            attack_vector['src_ports'] = []
        attack_vector['total_src_ports'] = len(attack_vector['src_ports'])

        if str(df_remaining['dstport'].iloc[0]) != 'nan':
            attack_vector['dst_ports'] = [int(x) for x in df_remaining['dstport'].unique().tolist() if
                                          not math.isnan(x)]
        else:
            attack_vector['dst_ports'] = []
        attack_vector['total_dst_ports'] = len(attack_vector['dst_ports'])

        attack_vector['start_timestamp'] = df_remaining['frame.time_epoch'].iloc[0]
        attack_vector['key'] = str(hashlib.md5(str(attack_vector['start_timestamp']).encode()).hexdigest())
        attack_vector['start_time'] = datetime.fromtimestamp(attack_vector['start_timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        attack_vector['duration_sec'] = df_remaining['frame.time_epoch'].iloc[-1] - attack_vector['start_timestamp']
        attack_vector['total_packets'] = len(df_remaining)
        attack_vector['avg_pps'] = attack_vector['total_packets']/attack_vector['duration_sec']
        
        attack_vector_current_size = 0
        for i in range(0,attack_vector['total_packets']):
            attack_vector_current_size += df_remaining['frame.len'].iloc[i]            
        attack_vector['avg_bps'] = attack_vector_current_size/attack_vector['duration_sec']

        print("STEP 3.6: Analysing the TTL variation (max-min) for all source IPs...")
        #ttl_variations = df_remaining.groupby(['_ws.col.Source'])['ip.ttl'].apply(lambda x: x.apply(lambda y: int(y))).agg(np.ptp).value_counts().sort_index()
        #print("TTL DELTA VARIATION (max - min) FOR SOURCE IPS [delta num_src_ips]:")
        #print(ttl_variations)
        #print('********************************************************************************************')

        print("TTL VALUE DISTRIBUTION:")
        print(df_remaining['ip.ttl'].value_counts().head())
        
        attack_vector['vector'] = str(attack_vector_filter_string).replace("df_saved", "")

        print("ATTACK VECTOR " + str(counter) + ": " + str(attack_vector['vector']))
        print("  - Packets:" + str(attack_vector['total_packets']))
        print("  - #Src_IPs:" + str(attack_vector['total_src_ips']))

        fingerprints.append(attack_vector)

        print("\n################################################################################")
        print("################################################################################\n")

        #In case of loop stop
        if len(fingerprints)>10:
            print("\nSTOP ANALYSIS; LOOKS LIKE A LOOP; RE-CHECK THE DISSECTOR SOURCE CODE!!")
            break

        df_saved = df_saved[eval(attack_vector_filter_string.replace('==', '!=').replace('&', '|'))]

        df_remaining = df_saved

        counter += 1
        attack_vector = {}


    ##Changing keys whether there are attack vectors with the same key   
    attackvector_keys = [x['key'] for x in fingerprints]
    for k, i in enumerate(attackvector_keys):
        repetition_times = attackvector_keys.count(i)
        if repetition_times >1:
            attackvector_keys[k]=i+'_'+str(repetition_times)
            repetition_times -=1   
    for k, i in enumerate(attackvector_keys):
        fingerprints[k]['key']=i

    ##Adding the multivector key to each attack vector
    for x in fingerprints:
        x['multivector_key']= fingerprints[0]['key']

    ##Comparing the source IPs involved in each attack vector
    matrix_source_ip_intersection = pd.DataFrame()
    for m in range(counter - 1):
        for n in range(counter - 1):
            intersection = len(np.intersect1d(attack_vector_source_ips[m], attack_vector_source_ips[n]))
            matrix_source_ip_intersection.loc[str(m + 1), str(n + 1)] = intersection
        matrix_source_ip_intersection.loc[str(m + 1),'Attack vector'] = str(attack_vector_labels[m])
    print("INTERSECTION OF SOURCE IPS IN ATTACK VECTORS:\n",matrix_source_ip_intersection)

    DNS_sourceIPS_unique = len(set(DNS_sourceIPS))

    return top1_dst_ip, fingerprints, DNS_sourceIPS_unique


def analyze_nfdump_dataframe(df_plus, dst_ip):
    """
    Analysis only top traffic stream
    :param df_plus: containing the pcap/pcapng file converted
    :return: (1) print the summary of attack vectors and
    """
    #debug = True
    total_packets = df_plus["i_packets"].sum()
    all_patterns = []
    attack_vector = {}
    attack_vector['file_type'] = 'netflow'
    counter = 1
    reflection_label = ""
    attack_vector_labels = []
    attack_vector_source_ips = []
    #spoofed_label = ""
    #fragment_label = ""
    threshold_1to1 = 0.4
    threshold_min_srcIPS = 3

    #STEP 1: Discovering Top 1 Destination IP
    print('STEP 3.1: Discovering Top 1 Destination IP...')
    if dst_ip:
        print("OUTPUT 3.1:", dst_ip)
        top1_dst_ip = dst_ip
    else:
        dst_ip_distribution = df_plus.groupby(by=['dst_ip'])['i_packets'].sum().sort_values(ascending=False).head()
        print("\nDISTRIBUTION OF TOP DESTINATION IPS:", dst_ip_distribution)
        top1_dst_ip = dst_ip_distribution.keys()[0]
        print("\nOUTPUT 3.1:", top1_dst_ip)
    print('********************************************************************************************')

    df_remaining = df_plus[df_plus['dst_ip'] == top1_dst_ip]

    ## a variable is needed to save the data, as df_remaining will be changed in the while-loop to make the code clearer
    df_saved = df_remaining

    num_considered_packets = df_remaining['i_packets'].sum()

    while len(df_remaining) > 1 :

        # Analyse the distribution of IP protocols (and defining the top1)
        #STEP 2: Discovering Top 1 IP Protocol
        print('STEP 3.2: Discovering Top 1 IP Protocol...')
        protocol_distribution = df_remaining.groupby(by=['ip_protocol'])['i_packets'].sum().sort_values(ascending=False).head()
        print("\nDISTRIBUTION OF TOP IP PROTOCOLS:",protocol_distribution)
        top1_protocol = protocol_distribution.keys()[0]
        attack_vector['ip_protocol'] = top1_protocol
        print('\nOUTPUT 3.2:', top1_protocol)
        

       #adding the findings to the attack_vector_filter 
        attack_vector_filter_string = ""
        attack_vector_filter_string = "(df_saved['ip_protocol'] == '" + str(top1_protocol) + "')"

        #Filtering the trace 
        df_remaining = df_remaining[df_remaining['ip_protocol'] == top1_protocol]
        
        # Calculating the number of packets after the first filter
        total_packets_filtered = df_remaining['i_packets'].sum()

        print('********************************************************************************************')

        if (top1_protocol != 'ICMP'):
        # Calculate the distribution of source ports based on the first filter

            print('STEP 3.3: Discovering Top 1 Port')
            percent_src_ports = df_remaining.groupby(by=['src_port'])['i_packets'].sum().sort_values(
                ascending=False).divide(float(total_packets_filtered) )
            print("\nDISTRIBUTION OF SOURCE PORT:",percent_src_ports.head()) 

                # Calculate the distribution of destination ports after the first filter
            percent_dst_ports = df_remaining.groupby(by=['dst_port'])['i_packets'].sum().sort_values(
                ascending=False).divide(float(total_packets_filtered) )

            print("\nDISTRIBUTION OF DESTINATION PORTS:", percent_dst_ports.head())

            
            if (len(percent_src_ports) > 0) and (len(percent_dst_ports) > 0):
                if percent_src_ports.values[0] > percent_dst_ports.values[0]:
                    print("\nOUTPUT 3.3: The highest frequency is SOURCE port: ", percent_src_ports.keys()[0])
                    df_remaining = df_remaining[df_remaining['src_port'] == percent_src_ports.keys()[0]]
                    attack_vector_filter_string +="&(df_saved['src_port'] == " + str(percent_src_ports.keys()[0]) + ")"
                    #filter_p2 = "false"

                    print('********************************************************************************************')
                    print('STEP 3.4: Analysing top 1 DESTINATION port frequency and THRESHOLD')
                    print('THRESHOLD =', threshold_1to1)
                
                    if (top1_protocol != 'ICMP') and (percent_dst_ports.values[0] > threshold_1to1):
                        filter_top2_p = "df_saved['dst_port']==" + str(percent_dst_ports.keys()[0])
                        df_remaining = df_remaining[df_remaining['dst_port'] == percent_dst_ports.keys()[0]]
                        #filter_p2 = "true"
                        value_dest_dis = percent_dst_ports.values[0]
                        attack_vector_filter_string +="&(df_saved['dst_port'] == " + str(percent_dst_ports.keys()[0]) + ")"
                        print('\nOUTPUT 3.4: DESTINATION port',percent_dst_ports.keys()[0], 'is considered as part of the attack vector.' )
                    else:
                        print('\nOUTPUT 3.4: DESTINATION port',percent_dst_ports.keys()[0], 'is NOT considered as part of the attack vector.' )


                else:
                    print("\nOUTPUT 3.3: The highest frequency is DESTINATION port: ", percent_dst_ports.keys()[0])    
                    df_remaining = df_remaining[df_remaining['dst_port'] == percent_dst_ports.keys()[0]]
                    attack_vector_filter_string +="&(df_saved['dst_port'] == " + str(percent_dst_ports.keys()[0]) + ")"
                    filter_top_p = "df_saved['dst_port']==" + str(percent_dst_ports.keys()[0])
                    #filter_p2 = "false"
                    print('********************************************************************************************')
                    print('STEP 3.4: Analysing top 1 SOURCE port frequency and THRESHOLD')
                    print('THRESHOLD =', threshold_1to1)
                
                    if (top1_protocol != 'ICMP') and (percent_src_ports.values[0] > threshold_1to1):
                        filter_top2_p = "df_saved['src_port']==" + str(percent_src_ports.keys()[0])
                        df_remaining = df_remaining[df_remaining['src_port'] == percent_src_ports.keys()[0]]
                        #filter_p2 = "true"
                        value_src_dis = percent_src_ports.values[0]
                        attack_vector_filter_string +="&(df_saved['src_port'] == " + str(percent_src_ports.keys()[0]) + ")"
                        print('\nOUTPUT 3.4: SOURCE port',percent_src_ports.keys()[0], 'is considered as part of the attack vector.' )
                    else:
                        print('\nOUTPUT 3.4: SOURCE port',percent_src_ports.keys()[0], 'is NOT considered as part of the attack vector.' )
                        
            print('********************************************************************************************')
            print("STEP 3.5: Analysing the Protocol for idenfying extra information")

            if (top1_protocol == 'UDP'):
                print("\nOUTPUT 3.5: There is NO extra information about UDP port",percent_src_ports.keys()[0], "in the network flow.")
                pattern_packets = df_remaining['i_packets'].sum()
                print('********************************************************************************************')
                
            if (top1_protocol == 'TCP'):
                # Check the existence of TCP flags
                tcp_flags_dis = df_remaining.groupby(by=['tcp_flag'])['i_packets'].sum().sort_values(
                    ascending=False) #.divide(float(pattern_packets) )
                print("Distribution of TCP flags", tcp_flags_dis)
                print("\nOUTPUT 3.5: TCP flag:", tcp_flags_dis.keys()[0])
                attack_vector_filter_string += "&(df_saved['tcp_flag'] == '" + str(tcp_flags_dis.keys()[0]) + "')"
                df_remaining = df_remaining[df_remaining['tcp_flag'] == tcp_flags_dis.keys()[0]]
                pattern_packets = df_remaining['i_packets'].sum()
                #percent_tcp_flags = df_remaining.groupby(by=['tcp_flag'])['i_packets'].sum().sort_values(
                    #ascending=False).divide(float(pattern_packets) )
                print('********************************************************************************************')


        else:
            print("STEP 3.5: Analysing the Protocol for idenfying extra information...")
            icmp_type_dis = df_remaining.groupby(by=['dst_port'])['i_packets'].sum().sort_values(ascending=False)
            print('\nDISTRIBUTION ICMP TYPES*:', icmp_type_dis)
            
            if (icmp_type_dis.keys()[0] > 767) and (icmp_type_dis.keys()[0] < 784):
                attack_vector['additional'] = 'icmp_type: 3'
                attack_vector_filter_string += "&(df_saved['dst_port'] < 784)"
                df_remaining = df_remaining[df_remaining['dst_port'] < 784]
                pattern_packets = df_remaining['i_packets'].sum()
                print("\nOUTPUT 3.5: ICMP type 3 is part of the attack")

            elif (icmp_type_dis.keys()[0] == 2816) or (icmp_type_dis.keys()[0] == 2817):
                attack_vector['additional'] = 'icmp_type: 11' 
                attack_vector_filter_string += "&(df_saved['dst_port'] > 2815)"
                df_remaining = df_remaining[df_remaining['dst_port'] > 2815]
                pattern_packets = df_remaining['i_packets'].sum()
                print("\nOUTPUT 3.5: ICMP type 11 is part of the attack")

            elif (icmp_type_dis.keys()[0] == 1281):
                attack_vector['additional'] = 'icmp_type: 5' 
                attack_vector_filter_string += "&(df_saved['dst_port'] == 1281)"
                df_remaining = df_remaining[df_remaining['dst_port'] == 1281]
                pattern_packets = df_remaining['i_packets'].sum()
                print("\nOUTPUT 3.5: ICMP type 5 is part of the attack")

            else:
                icmp_port = "df_saved['dst_port']==" + str(icmp_type_dis.keys()[0])
                df_remaining = df_remaining[df_remaining['dst_port'] == icmp_type_dis.keys()[0]]
                pattern_packets = df_remaining['i_packets'].sum()
                print("\nOUTPUT 3.5: ICMP of another type is part of the attack")

            print('********************************************************************************************')




            # Calculate the total number of packets involved in the attack
        attack_vector["total_packets"] = pattern_packets

            # Calculate the percentage of the current pattern compared to the raw input file
        representativeness = float(pattern_packets) * 100 / float(num_considered_packets)
        attack_vector["pattern_traffic_share"] = representativeness
        #attack_label = 'In %.2f' % representativeness + "\n " + attack_label

            # Calculating the number of source IPs involved in the attack
        ips_involved = df_remaining['src_ip'].unique()

        #attack_label = attack_label + "\n" + str(len(ips_involved)) + " source IPs"
        #attack_vector["src_ips"] = ips_involved.tolist()
        #attack_vector["total_src_ips"] = len(ips_involved)

        src_ips = []

        # Determine packet length avg, packet length deviation, ttl avg, ttl deviation, number of packets.
        for ip in ips_involved:
            #df_remaining: pd.DataFrame = df_remaining
            #df_ip = df_remaining.loc[df_remaining["src_ip"] == ip]
            df_ip = df_remaining[df_remaining["src_ip"] == ip]
            packets_sent = df_ip.shape[0]
            #avg_packet_length = df_ip["frame.len"].sum() / packets_sent
            #deviation_packet_length = df_ip["frame.len"].max() - df_ip["frame.len"].min()
            #df_ip["ip.ttl"] = df_ip["ip.ttl"].apply(lambda x: int(x))
            #avg_ttl = int(df_ip["ip.ttl"].sum()) / packets_sent
            #deviation_ttl = int(df_ip["ip.ttl"].max()) - int(df_ip["ip.ttl"].min())
            src_ips.append({
                "ip": ip,
                "pkt_count": packets_sent,
            #    "avg_pkt": avg_packet_length,
            #    "dev_pkt": deviation_packet_length,
            #    "avg_ttl": avg_ttl,
            #    "dev_ttl": deviation_ttl
            })

        src_ips = sorted(src_ips, key=lambda k: k['pkt_count'], reverse = 1)

        if "['src_port'] == 123)"in attack_vector_filter_string:
        	percentage_filter = 0.05
        else:
        	percentage_filter = 0

        threshold_filter = int(percentage_filter / 100 * len(src_ips))
        

        print("percentage for filter:",percentage_filter, ";threshold_filter: ", threshold_filter )
            
        src_ips_filtered = src_ips[: len(src_ips) - threshold_filter] 

        attack_vector["src_ips"] = src_ips_filtered
        attack_vector["total_src_ips"] = len(src_ips_filtered)


        if len(ips_involved) < threshold_min_srcIPS:
            print("DISCARTED ATTACK VECTOR " + str(counter) + ": " + str(attack_vector_filter_string).replace("df_saved", ""))
            print("  - Packets:" + str(attack_vector['total_packets']))
            print("  - #Src_IPs:" + str(attack_vector['total_src_ips']))
            print("\nSTOP ANALYSIS; THERE IS ONLY ONE SOURCE IP RELATED TO THIS ATTACK VECTOR!")
            print("################################################################################")
            print("################################################################################\n")
            break

        #print("\nPATTERN (ATTACK VECTOR) LABEL: " + str(counter) +  attack_vector_filter_string.replace("df_saved", ""))

        attack_vector_source_ips.append(ips_involved)
       

            # Calculating the number of source IPs involved in the attack
        attack_vector["start_times"] = df_remaining['start_time'].min()
        p = '%Y-%m-%d %H:%M:%S'
        # epoch is used as offset for the date and time
        epoch = datetime(1970, 1, 1,1)
        start_epoch = (datetime.strptime(df_remaining['start_time'].min(), p) - epoch).total_seconds()
        attack_vector["start_timestamp"] = str(start_epoch)
        #for checking if epoch is converted right.
        #dt_object = datetime.fromtimestamp(datat_epoch)
        #attack_vector["2. convertiert"] = str(dt_object)

        # end_timestamp not included in pcap
        #attack_vector["end_timestamp"] = df_remaining['start_time'].max()
        end_epoch = (datetime.strptime(df_remaining['start_time'].max(), p) - epoch).total_seconds()
        attack_vector["duration_sec"] = str(end_epoch - start_epoch)
        if (float(attack_vector["duration_sec"]) > 0):
            attack_vector["avg_pps"] = float(pattern_packets)/float(attack_vector["duration_sec"])
            attack_vector["avg_bps"] = df_remaining['i_bytes'].sum()/float(attack_vector["duration_sec"])
        else:
            attack_vector["avg_pps"] = 0
            attack_vector["avg_bps"] = 0
        attack_vector['key'] = str(hashlib.md5(str(start_epoch).encode()).hexdigest())

            # Calculating the distribution of source ports that remains
        percent_src_ports = df_remaining.groupby(by=['src_port'])['i_packets'].sum().sort_values(ascending=False).divide(float(pattern_packets) )
        attack_vector["src_ports"] = percent_src_ports.to_dict()
        attack_vector["total_src_ports"] = len(percent_src_ports)

            # Calculating the distribution of destination ports after the first filter
        percent_dst_ports = df_remaining.groupby(by=['dst_port'])['i_packets'].sum().sort_values(
            ascending=False).divide(float(pattern_packets) )
        attack_vector["dst_ports"] = percent_dst_ports.to_dict()
        attack_vector["total_dst_ports"] = len(attack_vector["dst_ports"])
        
            

            # There are 3 possibilities of attacks cases!
        # if percent_src_ports.values[0] == 100:
        #     #df_remaining = df_remaining[df_remaining['src_port'].isin(percent_src_ports.keys()) == False]
        #     df_remaining = df_remaining[df_remaining['src_port'].isin(percent_src_ports.keys()) == False]
        #     if len(percent_dst_ports) == 1 or value_dest_dis > threshold_1to1:
        #         if debug: print("\nCASE 1: 1 source port to 1 destination port")
        #         #print(filter)
        #         # if (top1_protocol != 'ICMP') and (filter_p2 == "true"):
        #         #     attack_vector_filter_string += '&(' + str(filter_top2_p) + ')'
        #         #     #ips_involved = df_remaining['src_ip'].unique()
        #         #     print(" new filter: ", attack_vector_filter_string)
        #         #     attack_vector["Protocol"] = portnumber2name(percent_src_ports.keys()[0])

        #             # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
        #         port_label = "From " + portnumber2name(
        #             percent_src_ports.keys()[0]) + "\n   - Against " + portnumber2name(
        #             percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
        #     else:
        #         if debug: print("\nCASE 2: 1 source port to a set of destination ports") #if debug else next
        #         if percent_dst_ports.values[0] >= 50:
        #             print("")
        #             # port_label = "From " + portnumber2name(
        #             #     percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
        #             #     len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
        #             #     percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
        #             #                  0] + "%]" + " and " + portnumber2name(
        #             #     percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
        #             #                  percent_dst_ports.values[
        #             #                  1] + "%]"
        #         elif percent_dst_ports.values[0] >= 33:
        #             port_label = "From " + portnumber2name(
        #                 percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
        #                 len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
        #                 percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
        #                              0] + "%]" + "; " + portnumber2name(
        #                     percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
        #                          percent_dst_ports.values[
        #                              1] + "%], and " + portnumber2name(
        #                 percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
        #         else:
        #             port_label = "From " + portnumber2name(
        #                 percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
        #                 len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
        #                 percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
        #                              0] + "%]" + "; " + portnumber2name(
        #                 percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
        #                              percent_dst_ports.values[
        #                              1] + "%], and " + portnumber2name(
        #                 percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
        # else:
        #     if len(percent_src_ports) == 1 or value_src_dis > threshold_1to1:
        #         #df_remaining = df_remaining[df_remaining['src_port'].isin(percent_src_ports.keys()) == False]
        #         df_remaining = df_remaining[df_remaining['src_port'].isin(percent_src_ports.keys()) == False]
        #         #filter_top2_p = "df_saved['src_port']==" + str(percent_src_ports.keys()[0])
        #         #attack_vector["2. selected_port"] = "src" + str(percent_src_ports.keys()[0])
        #         # if (top1_protocol != 'ICMP') and (filter_p2 == "true"):
        #         #     attack_vector_filter_string += '&(' + str(filter_top2_p) + ')'
        #         #     print(" new filter: ", attack_vector_filter_string)
        #         #     #ips_involved = df_remaining['src_ip'].unique()
        #         #     attack_vector["Protocol"] = portnumber2name(percent_src_ports.keys()[0])


        #         if debug: print("\nCASE 1: 1 source port to 1 destination port") #if debug else next
        #         port_label = "Using " + portnumber2name(percent_src_ports.keys()[0]) + "[" + '%.1f' % \
        #                      percent_src_ports.values[
        #                              0] + "%]" + "\n   - Against " + portnumber2name(
        #             percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                
        #     else:
        #         if debug: print("\nCASE 3: 1 source port to a set of destination ports") #if debug else next
        #         #df_remaining = df_remaining[df_remaining['src_port'].isin(percent_src_ports.keys()) == False]
        #         df_remaining = df_remaining[df_remaining['src_port'].isin(percent_src_ports.keys()) == False]

        #         if percent_src_ports.values[0] >= 50:
        #             port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
        #                          portnumber2name(percent_src_ports.keys()[0]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[0] + "%] and " + \
        #                          portnumber2name(percent_src_ports.keys()[1]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[1] + "%]" + "\n   - Against " + \
        #                          portnumber2name(percent_dst_ports.keys()[0]) + \
        #                          "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
        #         elif percent_src_ports.values[0] >= 33:
        #             port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
        #                          portnumber2name(percent_src_ports.keys()[0]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[0] + "%], " + \
        #                          portnumber2name(percent_src_ports.keys()[1]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[1] + "%], and " + \
        #                          portnumber2name(percent_src_ports.keys()[2]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[2] + "%]" + "\n   - Against " + \
        #                          portnumber2name(percent_dst_ports.keys()[0]) + \
        #                          "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
        #         else:
        #             #df_remaining = df_remaining[df_remaining['dst_port'].isin(percent_dst_ports.keys()) == False]
        #             df_remaining = df_remaining[df_remaining['dst_port'].isin(percent_dst_ports.keys()) == False]
        #             port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
        #                          portnumber2name(percent_src_ports.keys()[0]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[0] + "%], " + \
        #                          portnumber2name(percent_src_ports.keys()[1]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[1] + "%], " + \
        #                          portnumber2name(percent_src_ports.keys()[2]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[2] + "%]; and " + \
        #                          portnumber2name(percent_src_ports.keys()[3]) + \
        #                          "[" + '%.2f' % percent_src_ports.values[3] + "%]\n   - Against " + \
        #                          portnumber2name(percent_dst_ports.keys()[0]) + \
        #                          "[" + '%.1f' % percent_dst_ports.values[0] + "%]"



            # Testing HTTP request
        #if len(http_data) > 0 and ((percent_dst_ports.index[0] == 80) or (percent_dst_ports.index[0] == 443)):
        #    attack_label = attack_label + "; " + http_data.index[0]

            # Testing TCP flags
        #if (top1_protocol == 'TCP') and (len(percent_tcp_flags) > 0) and (percent_tcp_flags.values[0] > 50):
            #attack_label = attack_label + "; TCP flags: " + tcpflagletters2names(
            #percent_tcp_flags.index[0]) + "[" + '%.1f' % percent_tcp_flags.values[0] + "%]"

            # Must discuss if it actually stands for nfdump files
        if percent_src_ports.values[0] >= 1:
            attack_vector["reflected"] = True
            reflection_label = "Reflection & Amplification"
        attack_vector["vector"] = str(attack_vector_filter_string).replace("df_saved", "")
        attack_vector_labels.append(attack_vector_filter_string.replace("df_saved", ""))


        # print(
        #         "\nSUMMARY:\n" + "- %.2f" % representativeness + "% of the packets targeting " + top1_dst_ip + "\n" +
        #         "   - Involved " + str(len(ips_involved)) + " source IP addresses\n" +
        #         "   - Using IP protocol " + protocolnumber2name(top1_protocol) + "\n" +
        #         "   - " + port_label + "\n" +
        #         #"   - " + fragment_label +
        #         "   - " + reflection_label + "\n" +
        #         #"   - " + spoofed_label + "\n" +
        #         "   - " + "number of packets: " + str(pattern_packets))

        print("ATTACK VECTOR " + str(counter) + ": " + str(attack_vector_filter_string).replace("df_saved", ""))
        print("  - Packets:" + str(attack_vector['total_packets']))
        print("  - #Src_IPs:" + str(attack_vector['total_src_ips']))

        all_patterns.append(attack_vector)

        if len(all_patterns)>10:
            print("STOP ANALYSIS; LOOKS LIKE A LOOP; RE-CHECK THE DISSECTOR SOURCE CODE!!")
            break


        if (top1_protocol == 'ICMP'): 
            if (attack_vector['additional'] == 'icmp_type: 3'):
                df_saved = df_saved[eval(attack_vector_filter_string.replace('==', '!=').replace('&', '|').replace('<','>'))]
            elif (attack_vector['additional'] == 'icmp_type: 11' ):
                df_saved = df_saved[eval(attack_vector_filter_string.replace('==', '!=').replace('&', '|').replace('>','<'))]
            else:
                df_saved = df_saved[eval(attack_vector_filter_string.replace('==', '!=').replace('&', '|'))]
        else:
            df_saved = df_saved[eval(attack_vector_filter_string.replace('==', '!=').replace('&', '|'))]


        df_remaining = df_saved
        counter +=1
        attack_vector = {}
        print("\n********************************************************************************")
        print("********************************************************************************\n")

    #Changing keys whether there are attack vectors with the same key   
    attackvector_keys = [x['key'] for x in all_patterns]
    for k, i in enumerate(attackvector_keys):
        repetition_times = attackvector_keys.count(i)
        if repetition_times >1:
            attackvector_keys[k]=i+'_'+str(repetition_times)
            repetition_times -=1   
    for k, i in enumerate(attackvector_keys):
        all_patterns[k]['key']=i



    for x in all_patterns:
        x['multivector_key']= all_patterns[0]['key']

    ##Comparing the source IPs involved in each attack vector
    matrix_source_ip_intersection = pd.DataFrame()
    for m in range(counter - 1):
        for n in range(counter - 1):
            intersection = len(np.intersect1d(attack_vector_source_ips[m], attack_vector_source_ips[n]))
            matrix_source_ip_intersection.loc[str(m + 1), str(n + 1)] = intersection
        matrix_source_ip_intersection.loc[str(m + 1),'Attack vector'] = str(attack_vector_labels[m])
    print("INTERSECTION OF SOURCE IPS IN ATTACK VECTORS:\n",matrix_source_ip_intersection)

    DNS_sourceIPS_unique = 0

    return top1_dst_ip, all_patterns, DNS_sourceIPS_unique