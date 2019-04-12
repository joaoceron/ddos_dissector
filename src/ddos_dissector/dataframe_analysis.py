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

    df_attackvectors = []
    attack_vector_labels = []
    attack_vector_source_ips = []
    counter = 1

    
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

    while len(df_remaining) > 1 :
        
        # Analyse the distribution of IP protocols (and defining the top1)
        #STEP 3.2
        print('STEP 3.2: Discovering Top 1 IP Protocol...')

        protocol_distribution = df_remaining['ip.proto'].value_counts().head()
        print("\nDISTRIBUTION OF TOP IP PROTOCOLS: \n",protocol_distribution)
        top1_protocol = protocol_distribution.keys()[0]
        print("\nOUTPUT 3.2:", top1_protocol)
        print('********************************************************************************************')

        filter_top_protocol_string = "df_remaining['ip.proto']=='" + str(top1_protocol) + "'"
        attack_vector['ip_protocol'] = top1_protocol

        attack_vector_filter_string = ""

        # Define if the remaining is based on the top1 source OR destination port
        if top1_protocol == 'IPv4':
            fragmentation_distribution = df_remaining[df_remaining['ip.proto'] == 'IPv4']['fragmentation'].value_counts()
            print("DISTRIBUTION OF FRAGMENTATION:", fragmentation_distribution)

            if fragmentation_distribution.keys()[0]:
                filter_fragmentation_string = "df_remaining['fragmentation']==True"
                attack_vector_filter_string = '(' + str(filter_top_protocol_string) + ')&(' + str(
                    filter_fragmentation_string) + ')'
            attack_vector['additional'] = {'fragmentation': True}

        else:
            # Analyse the distribution of SOURCE ports AND define the top1
            print('STEP 3.3A: Discovering Top 1 Src Port')
            port_source_distribution = df_remaining[df_remaining['ip.proto'] == top1_protocol]['srcport'].value_counts(normalize=True).head()
            print("\nDISTRIBUTION OF TOP SOURCE PORT: \n", port_source_distribution)

            top1_source_port = math.floor(port_source_distribution.keys()[0])

            # Analyse the distribution of DESTINATION ports AND define the top1
            print('\nSTEP 3.3B: Discovering Top 1 Dest Port')
            port_destination_distribution = df_remaining[df_remaining['ip.proto'] == top1_protocol]['dstport'].value_counts(normalize=True).head()
            print("\nDISTRIBUTION OF TOP DESTINATION PORTS: \n",port_destination_distribution)
            top1_destination_port = math.floor(port_destination_distribution.keys()[0])
            print('********************************************************************************************')

            # Check which port type (source or destination) AND number had most occurrences
            if port_source_distribution.iloc[0] > port_destination_distribution.iloc[0]:
                filter_top_port = "df_remaining['srcport']==" + str(top1_source_port)
            else:
                filter_top_port = "df_remaining['dstport']==" + str(top1_destination_port)

            # Define the conclusion of the analysis (of the remaining traffic)
            attack_vector_filter_string = '(' + str(filter_top_protocol_string) + ')&(' + str(filter_top_port) + ')'

            #Analysis for ICMP
            if top1_protocol == 'ICMP':
                
                icmp_type_distribution = df_remaining[df_remaining['ip.proto'] == 'ICMP']['icmp.type'].value_counts()
                print("DISTRIBUTION OF TOP ICMP TYPES:", icmp_type_distribution)

                top1_icmp_type = icmp_type_distribution.keys()[0]
                filter_icmp_type = "df_remaining['icmp.type']=='" + str(top1_icmp_type)+"'"
                attack_vector_filter_string = '(' + str(filter_top_protocol_string) + ')&(' + str(filter_icmp_type) + ')'
                attack_vector['additional'] = {'icmp_type': top1_icmp_type}

                # if top1_protocol == 'QUIC':
                #     quic_payload_distribution = \
                #         df_remaining[df_remaining['ip.proto']=='QUIC']['quic.payload'].value_counts()
                #     if debug: print('DISTRIBUTION QUIC PAYLOADS:',quic_payload_distribution.head())
                #     top1_quic_payload_distribution = quic_payload_distribution.keys()[0]
                #     filter_quic = "df_remaining['quic.payload']=='"+str(top1_quic_payload_distribution)+"'"
                #     attack_vector_filter_string += '&('+str(filter_quic)+')'
                #
                #     attack_vector['additional'] = {'quic_payload':top1_quic_payload_distribution}
            
            #Analysis for TCP
            if top1_protocol == 'TCP':
                tcp_flag_distribution =  df_remaining[df_remaining['ip.proto'] == 'TCP']['tcp.flags.str'].value_counts().head()
                print("DISTRIBUTION OF TOP TCP FLAGS:",tcp_flag_distribution)
                top1_tcp_flag = tcp_flag_distribution.keys()[0]
                
                filter_tcp_flag = "df_remaining['tcp.flags.str']=='" + str(top1_tcp_flag) + "'"
                attack_vector_filter_string += '&(' + str(filter_tcp_flag) + ')'

                attack_vector['additional'] = {'tcp_flag': top1_tcp_flag}
            
            #Analysis for DNS
            if top1_protocol == 'DNS':
                dns_query_distribution = df_remaining[df_remaining['ip.proto'] == 'DNS']['dns.qry.name'].value_counts().head()
                print("DISTRIBUTION OF TOP DNS QUERIES:",dns_query_distribution)
                top1_dns_query = dns_query_distribution.keys()[0]

                filter_dns_query = "df_remaining['dns.qry.name']=='" + str(top1_dns_query) + "'"
                attack_vector_filter_string += '&(' + str(filter_dns_query) + ')'

                dns_type_distribution = df_remaining[df_remaining['ip.proto'] == 'DNS']['dns.qry.type'].value_counts().head()
                print("DISTRIBUTION OF TOP DNS TYPES:",dns_type_distribution)
                top1_dns_type = dns_type_distribution.keys()[0]
                
                attack_vector['additional'] = {
                    'dns_query': top1_dns_query,
                    'dns_type': top1_dns_type
                }
            
            #Analysis for NTP
            if top1_protocol == "NTP":
                ntp_mode_distribution = df_remaining[df_remaining['ip.proto'] == 'NTP']['ntp.priv.reqcode'].value_counts().head()
                print("DISTRIBUTION OF TOP NTP RESPONSE:",ntp_mode_distribution)
                top1_ntp_response = math.floor(ntp_mode_distribution.keys()[0])

                filter_ntp_response = "df_remaining['ntp.priv.reqcode']==" + str(top1_ntp_response) 
                attack_vector_filter_string += '&(' + str(filter_ntp_response) + ')'

                attack_vector['additional'] = {'ntp_reqcode': top1_ntp_response}


        attack_vector_labels.append(attack_vector_filter_string.replace("df_remaining", ""))

        df_attack_vector_current = df_remaining[eval(attack_vector_filter_string)]

        src_ips_attack_vector_current = df_attack_vector_current['_ws.col.Source'].unique()

        # If the number of source IPs involved in this potential attack vector is 1, then it is NOT a DDoS!
        if len(src_ips_attack_vector_current) < 2:
            print("DISCARTED ATTACK VECTOR " + str(counter) + ": " + str(attack_vector_filter_string).replace("df_remaining", ""))
            print("  - Packets:" + str(len(df_attack_vector_current)))
            print("  - #Src_IPs:" + str(len(src_ips_attack_vector_current)))
            print("\nSTOP ANALYSIS; THERE IS ONLY ONE SOURCE IP RELATED TO THIS ATTACK VECTOR!")
            print("################################################################################")
            print("################################################################################\n")
            break

        # For later comparing the list of IPs
        attack_vector_source_ips.append(src_ips_attack_vector_current)

        attack_vector['src_ips'] = src_ips_attack_vector_current.tolist()
        attack_vector['total_src_ips'] = len(attack_vector['src_ips'])

        if str(df_attack_vector_current['srcport'].iloc[0]) != 'nan':
            attack_vector['src_ports'] = [int(x) for x in df_attack_vector_current['srcport'].unique().tolist() if
                                          not math.isnan(x)]
        else:
            attack_vector['src_ports'] = []

        attack_vector['total_src_ports'] = len(attack_vector['src_ports'])

        if str(df_attack_vector_current['dstport'].iloc[0]) != 'nan':
            attack_vector['dst_ports'] = [int(x) for x in df_attack_vector_current['dstport'].unique().tolist() if
                                          not math.isnan(x)]
        else:
            attack_vector['dst_ports'] = []
        

        attack_vector['total_dst_ports'] = len(attack_vector['dst_ports'])
        attack_vector['start_timestamp'] = df_attack_vector_current['frame.time_epoch'].iloc[0]
        attack_vector['key'] = str(hashlib.md5(str(attack_vector['start_timestamp']).encode()).hexdigest())
        attack_vector['start_time'] = datetime.fromtimestamp(attack_vector['start_timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        attack_vector['duration_sec'] = df_attack_vector_current['frame.time_epoch'].iloc[-1] - attack_vector['start_timestamp']
        attack_vector['total_packets'] = len(df_attack_vector_current)
        attack_vector['avg_pps'] = attack_vector['total_packets']/attack_vector['duration_sec']
        
        attack_vector_current_size = 0
        for i in range(0,attack_vector['total_packets']):
            attack_vector_current_size += df_attack_vector_current['frame.len'].iloc[i]            
        attack_vector['avg_bps'] = attack_vector_current_size/attack_vector['duration_sec']

        # ttl_variations = \
        #     df_attack_vector_current.groupby(['_ws.col.Source'])['ip.ttl'].agg(np.ptp).value_counts().sort_index()
        # if debug:
        #     print("TTL VARIATION FOR IPS:")
        #     print(ttl_variations)
        #     print("TTL VALUE DISTRIBUTION:")
        #     print(df_attack_vector_current['ip.ttl'].value_counts().head())
        
        attack_vector['vector'] = str(attack_vector_filter_string).replace("df_remaining", "")

        print("ATTACK VECTOR " + str(counter) + ": " + str(attack_vector['vector']))
        print("  - Packets:" + str(attack_vector['total_packets']))
        print("  - #Src_IPs:" + str(attack_vector['total_src_ips']))

        fingerprints.append(attack_vector)

        print("################################################################################")
        print("################################################################################\n")

        #In case of loop stop
        if len(fingerprints)>10:
            print("\nSTOP ANALYSIS; LOOKS LIKE A LOOP; RE-CHECK THE DISSECTOR SOURCE CODE!!")
            break

        df_remaining = df_remaining[eval(attack_vector_filter_string.replace('==', '!=').replace('&', '|'))]

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
        matrix_source_ip_intersection.loc[str(m + 1), 'Attack vector'] = str(attack_vector_labels[m])
    print("INTERSECTION OF SOURCE IPS IN ATTACK VECTORS:",matrix_source_ip_intersection)

    return top1_dst_ip, fingerprints


def analyze_nfdump_dataframe(df_plus, dst_ip):
    """
    Analysis only top traffic stream
    :param df_plus: containing the pcap/pcapng file converted
    :return: (1) print the summary of attack vectors and
    """
    debug = True
    total_packets = df_plus["i_packets"].sum()
    all_patterns = []
    attack_vector = {}
    attack_vector['file_type'] = 'netflow'
    counter = 1
    #attack_case = "-1"
    reflection_label = ""
    spoofed_label = ""
    fragment_label = ""
    threshold_1to1 = 0.4

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

    df_filtered = df_plus[df_plus['dst_ip'] == top1_dst_ip]

    ## a variable is needed to save the data, as df_filtered will be changed in the while-loop to make the code clearer
    df_saved = df_filtered

    num_considered_packets = df_filtered['i_packets'].sum()

    while len(df_filtered) > 1 :

        # Analyse the distribution of IP protocols (and defining the top1)
        #STEP 2: Discovering Top 1 IP Protocol
        print('STEP 3.2: Discovering Top 1 IP Protocol...')
        protocol_distribution = df_filtered.groupby(by=['ip_protocol'])['i_packets'].sum().sort_values(ascending=False).head()
        print("\nDISTRIBUTION OF TOP IP PROTOCOLS:",protocol_distribution)
        top1_protocol = protocol_distribution.keys()[0]
        attack_vector['ip_protocol'] = top1_protocol
        print('\nOUTPUT 3.2:', top1_protocol)
        print('********************************************************************************************')

       #adding the findings to the attack_vector_filter 
        attack_vector_filter_string = ""
        attack_vector_filter_string = "(df_saved['ip_protocol'] == '" + str(top1_protocol) + "')"

        #Filtering the trace 
        df_filtered = df_filtered[df_filtered['ip_protocol'] == top1_protocol]
        
        # Calculating the number of packets after the first filter
        total_packets_filtered = df_filtered['i_packets'].sum()

        # Calculate the distribution of source ports based on the first filter
        print('STEP 3.3: Discovering Top 1 Port')
        percent_src_ports = df_filtered.groupby(by=['src_port'])['i_packets'].sum().sort_values(
            ascending=False).divide(float(total_packets_filtered) )
        print("\nDISTRIBUTION OF SOURCE PORT:",percent_src_ports.head()) 

            # Calculate the distribution of destination ports after the first filter
        percent_dst_ports = df_filtered.groupby(by=['dst_port'])['i_packets'].sum().sort_values(
            ascending=False).divide(float(total_packets_filtered) )

        print("\nDISTRIBUTION OF DESTINATION PORTS:", percent_dst_ports.head())

        #reset value for recognizing an own attack
        value_src_dis = 0
        value_dest_dis = 0

        
        if (len(percent_src_ports) > 0) and (len(percent_dst_ports) > 0):
            if percent_src_ports.values[0] > percent_dst_ports.values[0]:
                print("\nOUTPUT 3.3: The highest frequency is SOURCE port: ", percent_src_ports.keys()[0])
                df_pattern = df_filtered[df_filtered['src_port'] == percent_src_ports.keys()[0]]
                attack_vector_filter_string +="&(df_saved['src_port'] == '" + str(percent_src_ports.keys()[0]) + "')"
                #filter_top_p = "df_saved['src_port']==" + str(percent_src_ports.keys()[0])
                filter_p2 = "false"

                print('********************************************************************************************')
                print('STEP 3.4: Analysing top 1 DESTINATION port frequency and THRESHOLD')
                print('THRESHOLD =', threshold_1to1)
                #attack_vector["selected_port"] = "src" + str(percent_src_ports.keys()[0])
                #attack_vector_filter_string += '&(' + str(filter_src_port) + ')'

                #filter = "src"
                
                if (top1_protocol != 'ICMP') and (percent_dst_ports.values[0] > threshold_1to1):
                    filter_top2_p = "df_saved['dst_port']==" + str(percent_dst_ports.keys()[0])
                    df_pattern = df_pattern[df_pattern['dst_port'] == percent_dst_ports.keys()[0]]
                    filter_p2 = "true"
                    value_dest_dis = percent_dst_ports.values[0]
                    attack_vector_filter_string +="&(df_saved['dst_port'] == '" + str(percent_dst_ports.keys()[0]) + "')"
                    #filter = "src"
                    print('\nOUTPUT 3.4: DESTINATION port',percent_dst_ports.keys()[0], 'is considered as part of the attack vector.' )
                else:
                    print('\nOUTPUT 3.4: DESTINATION port',percent_dst_ports.keys()[0], 'is NOT considered as part of the attack vector.' )


            else:
                    
                df_pattern = df_filtered[df_filtered['dst_port'] == percent_dst_ports.keys()[0]]
                attack_vector_filter_string +="&(df_saved['dst_port'] == '" + str(percent_dst_ports.keys()[0]) + "')"
                filter_top_p = "df_saved['dst_port']==" + str(percent_dst_ports.keys()[0])
                filter_p2 = "false"
                print('********************************************************************************************')
                print('STEP 3.4: Analysing top 1 SOURCE port frequency and THRESHOLD')
                print('THRESHOLD =', threshold_1to1)
                #attack_vector["selected_port"] = "dst" + str(percent_dst_ports.keys()[0])
                #attack_vector_filter_string += '&(' + str(filter_dst_port) + ')'

                if (top1_protocol != 'ICMP') and (percent_src_ports.values[0] > threshold_1to1):
                    filter_top2_p = "df_saved['src_port']==" + str(percent_src_ports.keys()[0])
                    df_pattern = df_pattern[df_pattern['src_port'] == percent_src_ports.keys()[0]]
                    filter_p2 = "true"
                    value_src_dis = percent_src_ports.values[0]
                    attack_vector_filter_string +="&(df_saved['src_port'] == '" + str(percent_src_ports.keys()[0]) + "')"
                    #filter = "dst"
                    print('OUTPUT 3.4: SOURCE port',percent_src_ports.keys()[0], 'is considered as part of the attack vector.' )
                else:
                    print('OUTPUT 3.4: SOURCE port',percent_src_ports.keys()[0], 'is NOT considered as part of the attack vector.' )
                    
        print(attack_vector_filter_string)
        print('********************************************************************************************')

    
        #else:
            #if debug:
                #print('No top source/destination port')

            #return None


        if (top1_protocol == 'ICMP'): 
            icmp_type_dis = df_filtered.groupby(by=['dst_port'])['i_packets'].sum().sort_values(ascending=False)
            if debug: print('\nDISTRIBUTION ICMP TYPES:\n', icmp_type_dis)
            if (percent_dst_ports.keys()[0] > 767) and (percent_dst_ports.keys()[0] < 784):
                attack_vector['additional'] = 'icmp_type: 3'
                icmp_port = "df_saved['dst_port'] < 784"
                df_pattern = df_filtered[df_filtered['dst_port'] < 784]
                pattern_packets = df_pattern['i_packets'].sum()
                print("Packets of ICMP Type 3", pattern_packets)
            elif (percent_dst_ports.keys()[0] == 2816) or (percent_dst_ports.keys()[0] == 2817):
                attack_vector['additional'] = 'icmp_type: 11' 
                icmp_port = "df_saved['dst_port'] > 2815"
                df_pattern = df_filtered[df_filtered['dst_port'] > 2815]
                pattern_packets = df_pattern['i_packets'].sum()
                print("Packets of ICMP Type 11", pattern_packets)
            elif (percent_dst_ports.keys()[0] == 1281):
                attack_vector['additional'] = 'icmp_type: 5' 
                icmp_port = "df_saved['dst_port'] == 1281"
                df_pattern = df_filtered[df_filtered['dst_port'] == 1281]
                pattern_packets = df_pattern['i_packets'].sum()
                print("Packets of ICMP Type 5", pattern_packets)
            else:
                icmp_port = "df_saved['dst_port']==" + str(percent_dst_ports.keys()[0])
                attack_vector['additional'] = 'icmp_type: not specified' 
                df_pattern = df_filtered[df_filtered['dst_port'] == percent_dst_ports.keys()[0]]
                pattern_packets = df_pattern['i_packets'].sum()
                print("Packets of this ICMP attack ", pattern_packets)


            #attack_vector_filter_string = '('+ str(filter_top_protocol_string) + ')&(' + str(icmp_port) + ')'



        if (top1_protocol == 'UDP'): #(top1_protocol == 'TCP') or :
           # attack_vector_filter_string = '('+ str(filter_top_protocol_string) + ')&(' + str(filter_top_p) + ')'
            pattern_packets = df_pattern['i_packets'].sum()




        if (top1_protocol == 'TCP'):
            # Check the existence of TCP flags
            tcp_flags_dis = df_pattern.groupby(by=['tcp_flag'])['i_packets'].sum().sort_values(
                ascending=False) #.divide(float(pattern_packets) )
            if debug:
                print("Distribution of TCP flags", tcp_flags_dis)
            top_tcp_flags = tcp_flags_dis.keys()[0]
            filter_tcp_flag = "df_saved['tcp_flag'] == '" + top_tcp_flags + "'"
            #attack_vector_filter_string = '('+ str(filter_top_protocol_string) + ')&(' + str(filter_top_p) + ')&(' + str(filter_tcp_flag) + ')'
            df_pattern = df_pattern[df_pattern['tcp_flag'] == tcp_flags_dis.keys()[0]]
            pattern_packets = df_pattern['i_packets'].sum()
            percent_tcp_flags = df_pattern.groupby(by=['tcp_flag'])['i_packets'].sum().sort_values(
                ascending=False).divide(float(pattern_packets) )





            # Calculate the total number of packets involved in the attack
        attack_vector["pattern_packet_count"] = pattern_packets

            # Calculate the percentage of the current pattern compared to the raw input file
        representativeness = float(pattern_packets) * 100 / float(num_considered_packets)
        attack_vector["pattern_traffic_share"] = representativeness
        #attack_label = 'In %.2f' % representativeness + "\n " + attack_label



            # Calculating the number of source IPs involved in the attack
        ips_involved = df_pattern['src_ip'].unique()
        if len(ips_involved) < 3:
            if debug:
                print("\nNO MORE PATTERNS")
            break

        if debug:
            print("\nPATTERN (ATTACK VECTOR) LABEL: " + str(counter) +  attack_vector_filter_string.replace("df_saved", ""))

        #attack_label = attack_label + "\n" + str(len(ips_involved)) + " source IPs"
        attack_vector["src_ips"] = ips_involved.tolist()
        attack_vector["total_src_ips"] = len(ips_involved)

            # Calculating the number of source IPs involved in the attack
        attack_vector["start_times"] = df_pattern['start_time'].min()
        p = '%Y-%m-%d %H:%M:%S'
        # epoch is used as offset for the date and time
        epoch = datetime(1970, 1, 1,1)
        start_epoch = (datetime.strptime(df_pattern['start_time'].min(), p) - epoch).total_seconds()
        attack_vector["start_timestamp"] = str(start_epoch)
        #for checking if epoch is converted right.
        #dt_object = datetime.fromtimestamp(datat_epoch)
        #attack_vector["2. convertiert"] = str(dt_object)

        # end_timestamp not included in pcap
        #attack_vector["end_timestamp"] = df_pattern['start_time'].max()
        end_epoch = (datetime.strptime(df_pattern['start_time'].max(), p) - epoch).total_seconds()
        attack_vector["duration_sec"] = str(end_epoch - start_epoch)
        if (float(attack_vector["duration_sec"]) > 0):
            attack_vector["avg_pps"] = float(pattern_packets)/float(attack_vector["duration_sec"])
            attack_vector["avg_bps"] = df_pattern['i_bytes'].sum()/float(attack_vector["duration_sec"])
        else:
            attack_vector["avg_pps"] = 0
            attack_vector["avg_bps"] = 0
        attack_vector['key'] = str(hashlib.md5(str(start_epoch).encode()).hexdigest())


        #if (top1_protocol == 'TCP') or (top1_protocol == 'UDP'):
            # Calculating the distribution of source ports that remains
        percent_src_ports = df_pattern.groupby(by=['src_port'])['i_packets'].sum().sort_values(ascending=False).divide(float(pattern_packets) )
        attack_vector["src_ports"] = percent_src_ports.to_dict()
        attack_vector["total_src_ports"] = len(percent_src_ports)

            # Calculating the distribution of destination ports after the first filter
        percent_dst_ports = df_pattern.groupby(by=['dst_port'])['i_packets'].sum().sort_values(
            ascending=False).divide(float(pattern_packets) )
        attack_vector["dst_ports"] = percent_dst_ports.to_dict()
        attack_vector["total_dst_ports"] = len(attack_vector["dst_ports"])
        
            

            # There are 3 possibilities of attacks cases!
        if percent_src_ports.values[0] == 100:
            #df_pattern = df_pattern[df_pattern['src_port'].isin(percent_src_ports.keys()) == False]
            df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]
            if len(percent_dst_ports) == 1 or value_dest_dis > threshold_1to1:
                if debug: print("\nCASE 1: 1 source port to 1 destination port")
                #print(filter)
                # if (top1_protocol != 'ICMP') and (filter_p2 == "true"):
                #     attack_vector_filter_string += '&(' + str(filter_top2_p) + ')'
                #     #ips_involved = df_filtered['src_ip'].unique()
                #     print(" new filter: ", attack_vector_filter_string)
                #     attack_vector["Protocol"] = portnumber2name(percent_src_ports.keys()[0])

                    # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                port_label = "From " + portnumber2name(
                    percent_src_ports.keys()[0]) + "\n   - Against " + portnumber2name(
                    percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
            else:
                if debug: print("\nCASE 2: 1 source port to a set of destination ports") #if debug else next
                if percent_dst_ports.values[0] >= 50:
                    print("")
                    # port_label = "From " + portnumber2name(
                    #     percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                    #     len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                    #     percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                    #                  0] + "%]" + " and " + portnumber2name(
                    #     percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                    #                  percent_dst_ports.values[
                    #                  1] + "%]"
                elif percent_dst_ports.values[0] >= 33:
                    port_label = "From " + portnumber2name(
                        percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                        len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                        percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                                     0] + "%]" + "; " + portnumber2name(
                            percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                 percent_dst_ports.values[
                                     1] + "%], and " + portnumber2name(
                        percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
                else:
                    port_label = "From " + portnumber2name(
                        percent_src_ports.keys()[0]) + "\n   - Against a set of (" + str(
                        len(percent_dst_ports)) + ") ports, such as " + portnumber2name(
                        percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                                     0] + "%]" + "; " + portnumber2name(
                        percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                     percent_dst_ports.values[
                                     1] + "%], and " + portnumber2name(
                        percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
        else:
            if len(percent_src_ports) == 1 or value_src_dis > threshold_1to1:
                #df_pattern = df_pattern[df_pattern['src_port'].isin(percent_src_ports.keys()) == False]
                df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]
                #filter_top2_p = "df_saved['src_port']==" + str(percent_src_ports.keys()[0])
                #attack_vector["2. selected_port"] = "src" + str(percent_src_ports.keys()[0])
                if (top1_protocol != 'ICMP') and (filter_p2 == "true"):
                    attack_vector_filter_string += '&(' + str(filter_top2_p) + ')'
                    print(" new filter: ", attack_vector_filter_string)
                    #ips_involved = df_filtered['src_ip'].unique()
                    attack_vector["Protocol"] = portnumber2name(percent_src_ports.keys()[0])


                if debug: print("\nCASE 1: 1 source port to 1 destination port") #if debug else next
                port_label = "Using " + portnumber2name(percent_src_ports.keys()[0]) + "[" + '%.1f' % \
                             percent_src_ports.values[
                                     0] + "%]" + "\n   - Against " + portnumber2name(
                    percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                
            else:
                if debug: print("\nCASE 3: 1 source port to a set of destination ports") #if debug else next
                #df_pattern = df_pattern[df_pattern['src_port'].isin(percent_src_ports.keys()) == False]
                df_filtered = df_filtered[df_filtered['src_port'].isin(percent_src_ports.keys()) == False]

                if percent_src_ports.values[0] >= 50:
                    port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
                                 portnumber2name(percent_src_ports.keys()[0]) + \
                                 "[" + '%.2f' % percent_src_ports.values[0] + "%] and " + \
                                 portnumber2name(percent_src_ports.keys()[1]) + \
                                 "[" + '%.2f' % percent_src_ports.values[1] + "%]" + "\n   - Against " + \
                                 portnumber2name(percent_dst_ports.keys()[0]) + \
                                 "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                elif percent_src_ports.values[0] >= 33:
                    port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
                                 portnumber2name(percent_src_ports.keys()[0]) + \
                                 "[" + '%.2f' % percent_src_ports.values[0] + "%], " + \
                                 portnumber2name(percent_src_ports.keys()[1]) + \
                                 "[" + '%.2f' % percent_src_ports.values[1] + "%], and " + \
                                 portnumber2name(percent_src_ports.keys()[2]) + \
                                 "[" + '%.2f' % percent_src_ports.values[2] + "%]" + "\n   - Against " + \
                                 portnumber2name(percent_dst_ports.keys()[0]) + \
                                 "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                else:
                    #df_pattern = df_pattern[df_pattern['dst_port'].isin(percent_dst_ports.keys()) == False]
                    df_filtered = df_filtered[df_filtered['dst_port'].isin(percent_dst_ports.keys()) == False]
                    port_label = "From a set of (" + str(len(percent_src_ports)) + ") ports, such as " + \
                                 portnumber2name(percent_src_ports.keys()[0]) + \
                                 "[" + '%.2f' % percent_src_ports.values[0] + "%], " + \
                                 portnumber2name(percent_src_ports.keys()[1]) + \
                                 "[" + '%.2f' % percent_src_ports.values[1] + "%], " + \
                                 portnumber2name(percent_src_ports.keys()[2]) + \
                                 "[" + '%.2f' % percent_src_ports.values[2] + "%]; and " + \
                                 portnumber2name(percent_src_ports.keys()[3]) + \
                                 "[" + '%.2f' % percent_src_ports.values[3] + "%]\n   - Against " + \
                                 portnumber2name(percent_dst_ports.keys()[0]) + \
                                 "[" + '%.1f' % percent_dst_ports.values[0] + "%]"



            # Testing HTTP request
        #if len(http_data) > 0 and ((percent_dst_ports.index[0] == 80) or (percent_dst_ports.index[0] == 443)):
        #    attack_label = attack_label + "; " + http_data.index[0]

            # Testing TCP flags
        if (top1_protocol == 'TCP') and (len(percent_tcp_flags) > 0) and (percent_tcp_flags.values[0] > 50):
            #attack_label = attack_label + "; TCP flags: " + tcpflagletters2names(
            #percent_tcp_flags.index[0]) + "[" + '%.1f' % percent_tcp_flags.values[0] + "%]"

            # Must discuss if it actually stands for nfdump files
        if percent_src_ports.values[0] >= 1:
            attack_vector["reflected"] = True
            reflection_label = "Reflection & Amplification"
        attack_vector["vector"] = str(attack_vector_filter_string).replace("df_saved", "")

        print(
                "\nSUMMARY:\n" + "- %.2f" % representativeness + "% of the packets targeting " + top1_dst_ip + "\n" +
                "   - Involved " + str(len(ips_involved)) + " source IP addresses\n" +
                "   - Using IP protocol " + protocolnumber2name(top1_protocol) + "\n" +
                "   - " + port_label + "\n" +
                #"   - " + fragment_label +
                "   - " + reflection_label + "\n" +
                #"   - " + spoofed_label + "\n" +
                "   - " + "number of packets: " + str(pattern_packets))

        all_patterns.append(attack_vector)

        if len(all_patterns)>10:
            if debug:
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

        df_filtered = df_saved
        counter +=1
        result = {}

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

   
    return top1_dst_ip, all_patterns