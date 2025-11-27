use std::ffi::c_void;
use std::fmt::Pointer;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use std::iter::Iterator;
use std::marker::PhantomData;

use libc::{free, malloc, wchar_t, wcslen};
use windows::Win32::{
    Foundation::{
        ERROR_BUFFER_OVERFLOW,
        ERROR_SUCCESS,
        WIN32_ERROR,
    },
    Networking::WinSock::{
        AF_INET,
        AF_INET6,
        AF_UNSPEC,
        SOCKADDR_IN,
        SOCKADDR_IN6,
    },
    NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_PREFIX,
        IF_TYPE_OTHER,
        IF_TYPE_ETHERNET_CSMACD,
        IF_TYPE_IEEE1394,
        IF_TYPE_PPP,
        IF_TYPE_TUNNEL,
        IF_TYPE_IEEE80211,
        IF_TYPE_SOFTWARE_LOOPBACK,
        IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_PREFIX_XP,
        IP_ADAPTER_UNICAST_ADDRESS_LH,
        ConvertInterfaceLuidToIndex,
        ConvertLengthToIpv4Mask,
        GetAdaptersAddresses,
    },
    NetworkManagement::Ndis::{
        NET_LUID_LH,
        IfOperStatusUp,
        IfOperStatusDown,
        IfOperStatusTesting,
        IfOperStatusUnknown,
        IfOperStatusDormant,
        IfOperStatusNotPresent,
        IfOperStatusLowerLayerDown,
    },
};

use crate::utils::hex::HexSlice;
use crate::utils::ffialloc::FFIAlloc;
use crate::{IFF_ETH, IFF_WIRELESS, IFF_TUN,IFF_LOOPBACK, Addr, Error, NetworkInterface, Status, NetworkInterfaceConfig, Result, V4IfAddr, V6IfAddr};
use crate::interface::Netmask;

type MacAddress = Option<String>;

macro_rules! iterable_raw_pointer {
    ($t: ty, $n: ident) => {
        impl IterableRawPointer for $t {
            type Pointer = *const $t;
            type Value = $t;

            fn next(&self) -> Self::Pointer {
                self.$n
            }
        }
    };
}

iterable_raw_pointer!(IP_ADAPTER_ADDRESSES_LH, Next);
iterable_raw_pointer!(IP_ADAPTER_PREFIX_XP, Next);
iterable_raw_pointer!(IP_ADAPTER_UNICAST_ADDRESS_LH, Next);

impl NetworkInterfaceConfig for NetworkInterface {
    fn filter(netifs: Vec<NetworkInterface>, flags: i32) -> Result<Vec<NetworkInterface>> {
        Ok(netifs.into_iter().filter(|netif| {
            if netif.flags == 0 || flags == 0 {
                return true;
            }
            netif.flags & flags == flags
        }).collect())
    }
    fn show() -> Result<Vec<NetworkInterface>> {
        // Allocate a 15 KB buffer to start with.
        let mut buffer_size: u32 = 15000;
        // Limit retries
        const MAX_TRIES: i32 = 10;
        let mut try_no = 1;

        let adapter_address = loop {
            let adapter_address = FFIAlloc::<IP_ADAPTER_ADDRESSES_LH>::alloc(buffer_size as usize).ok_or_else(|| {
                // Memory allocation failed for IP_ADAPTER_ADDRESSES struct
                Error::GetIfAddrsError(String::from("GetAdaptersAddresses"), 1)
            })?;

            let res = WIN32_ERROR(unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    GAA_FLAG_INCLUDE_PREFIX,
                    None,
                    Some(adapter_address.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                    &mut buffer_size,
                )
            });
            match res {
                ERROR_SUCCESS => {
                    break Ok(adapter_address);
                }
                ERROR_BUFFER_OVERFLOW => {
                    // The buffer size indicated by the `SizePointer` parameter is too small to hold the
                    // adapter information or the `AdapterAddresses` parameter is `NULL`. The `SizePointer`
                    // parameter returned points to the required size of the buffer to hold the adapter
                    // information.
                    //
                    // Source: https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#return-value
                    if try_no == MAX_TRIES {
                        break Err(Error::GetIfAddrsError(
                            "GetAdapterAddresses: alloc error".to_string(),
                            res.0 as i32,
                        ));
                    }
                    try_no += 1;
                }
                _ => {
                    break Err(Error::GetIfAddrsError(
                        "GetAdapterAddresses".to_string(),
                        res.0 as i32,
                    ));
                }
            }
        }?;

        // iterate over the contained structs
        let mut network_interfaces = Vec::<NetworkInterface>::new();

        for adapter_address in RawPointerWrapper::new(adapter_address.as_ptr()) {
            let name = make_adapter_address_name(adapter_address)?;
            let index = get_adapter_address_index(adapter_address)?;
            let mac_addr = make_mac_address(adapter_address);
            let status = get_adapter_operstatus(adapter_address);
            let mut network_interface = NetworkInterface {
                name,
                addr: Vec::new(),
                mac_addr,
                index,
                status: status, flags: get_adapter_flags(adapter_address),
            };

            for current_unicast_address in
                RawPointerWrapper::new(adapter_address.FirstUnicastAddress)
            {
                let address = current_unicast_address.Address;

                network_interface
                    .addr
                    .push(match unsafe { (*address.lpSockaddr).sa_family } {
                        AF_INET => {
                            let sockaddr = &unsafe { *(address.lpSockaddr as *const SOCKADDR_IN) };
                            Addr::V4(V4IfAddr {
                                ip: make_ipv4_addr(sockaddr),
                                broadcast: lookup_ipv4_broadcast_addr(adapter_address, sockaddr),
                                netmask: make_ipv4_netmask(current_unicast_address),
                            })
                        }
                        AF_INET6 => {
                            let sockaddr = &unsafe { *(address.lpSockaddr as *const SOCKADDR_IN6) };
                            Addr::V6(V6IfAddr {
                                ip: make_ipv6_addr(sockaddr)?,
                                broadcast: None,
                                netmask: make_ipv6_netmask(sockaddr),
                            })
                        }
                        _ => continue,
                    });
            }

            network_interfaces.push(network_interface);
        }

        Ok(network_interfaces)
    }
}

// Find broadcast address
//
// see https://docs.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
//
// On Windows Vista and later, the linked IP_ADAPTER_PREFIX structures pointed
// to by the FirstPrefix member include three IP adapter prefixes for each IPv4
// address assigned to the adapter. These include
// 0. the host IP address prefix
// 1. the subnet IP address prefix
// 2. and the subnet broadcast IP address prefix. << we want these
// In addition, for each adapter with n IP adresses there are (not used)
// 3*n + 0. multicast address prefix
// 3*n + 1. and a broadcast address prefix.sb
//
// The order of addresses in prefix list and unicast list is not guaranteed to
// be the same, so we search for the unicast address in the prefix list, and
// then the broadcast address is next in list.
fn lookup_ipv4_broadcast_addr(
    adapter_address: &IP_ADAPTER_ADDRESSES_LH,
    unicast_ip: &SOCKADDR_IN,
) -> Option<Ipv4Addr> {
    let mut prefix_index_v4 = 0;
    let mut broadcast_index: Option<i32> = None;

    // Find adapter
    for prefix_address in RawPointerWrapper::new(adapter_address.FirstPrefix) {
        let address = prefix_address.Address;

        if unsafe { (*address.lpSockaddr).sa_family } == AF_INET {
            let sockaddr = &unsafe { *(address.lpSockaddr as *const SOCKADDR_IN) };

            if let Some(broadcast_index) = broadcast_index {
                if prefix_index_v4 == broadcast_index {
                    return Some(make_ipv4_addr(sockaddr));
                }
            } else if prefix_index_v4 % 3 == 1 && ipv4_addr_equal(sockaddr, unicast_ip) {
                broadcast_index = Some(prefix_index_v4 + 1);
            }
            prefix_index_v4 += 1;
        }
    }
    None
}

/// Retrieves the network interface name
fn make_adapter_address_name(adapter_address: &IP_ADAPTER_ADDRESSES_LH) -> Result<String> {
    Ok(unsafe {
        adapter_address.FriendlyName.to_string().map_err(Error::from)
    }?)
}

/// Creates a `Ipv6Addr` from a `SOCKADDR_IN6`
fn make_ipv6_addr(sockaddr: &SOCKADDR_IN6) -> Result<Ipv6Addr> {
    let address_bytes = unsafe { sockaddr.sin6_addr.u.Byte };
    let ip = Ipv6Addr::from(address_bytes);

    Ok(ip)
}

/// Creates a `Ipv4Addr` from a `SOCKADDR_IN`
fn make_ipv4_addr(sockaddr: &SOCKADDR_IN) -> Ipv4Addr {
    let address = unsafe { sockaddr.sin_addr.S_un.S_addr };

    if cfg!(target_endian = "little") {
        // due to a difference on how bytes are arranged on a
        // single word of memory by the CPU, swap bytes based
        // on CPU endianess to avoid having twisted IP addresses
        //
        // refer: https://github.com/rust-lang/rust/issues/48819
        return Ipv4Addr::from(address.swap_bytes());
    }

    Ipv4Addr::from(address)
}

/// Compare 2 ipv4 addresses.
fn ipv4_addr_equal(sockaddr1: &SOCKADDR_IN, sockaddr2: &SOCKADDR_IN) -> bool {
    let address1 = unsafe { sockaddr1.sin_addr.S_un.S_addr };
    let address2 = unsafe { sockaddr2.sin_addr.S_un.S_addr };
    address1 == address2
}

/// This function relies on the `GetAdapterAddresses` API which is available only on Windows Vista
/// and later versions.
///
/// An implementation of `GetIpAddrTable` to get all available network interfaces would be required
/// in order to support previous versions of Windows.
fn make_ipv4_netmask(unicast_address: &IP_ADAPTER_UNICAST_ADDRESS_LH) -> Netmask<Ipv4Addr> {
    let mut mask: u32 = 0;
    let on_link_prefix_length = unicast_address.OnLinkPrefixLength;
    unsafe {
        ConvertLengthToIpv4Mask(on_link_prefix_length as u32, &mut mask as *mut u32);
    }

    if cfg!(target_endian = "little") {
        // due to a difference on how bytes are arranged on a
        // single word of memory by the CPU, swap bytes based
        // on CPU endianess to avoid having twisted IP addresses
        //
        // refer: https://github.com/rust-lang/rust/issues/48819
        return Some(Ipv4Addr::from(mask.swap_bytes()));
    }

    Some(Ipv4Addr::from(mask))
}

fn make_ipv6_netmask(_sockaddr: &SOCKADDR_IN6) -> Netmask<Ipv6Addr> {
    None
}

/// Creates MacAddress from AdapterAddress
fn make_mac_address(adapter_address: &IP_ADAPTER_ADDRESSES_LH) -> MacAddress {
    // see https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#examples
    let mac_addr_len = adapter_address.PhysicalAddressLength as usize;
    match mac_addr_len {
        0 => None,
        len => Some(format!(
            "{}",
            HexSlice::new(&adapter_address.PhysicalAddress[..len])
        )),
    }
}

fn get_adapter_address_index(adapter_address: &IP_ADAPTER_ADDRESSES_LH) -> Result<u32> {
    let adapter_luid = &adapter_address.Luid;

    let index = &mut 0u32 as *mut u32;

    match unsafe { ConvertInterfaceLuidToIndex(adapter_luid, index) } {
        ERROR_SUCCESS => Ok(unsafe { *index }),
        e => Err(crate::error::Error::GetIfNameError(
            "ConvertInterfaceLuidToIndex".to_string(),
            e.0,
        )),
    }
}

/// Get interface status 
/// 
/// reference https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
/// 
fn get_adapter_operstatus(adapter_address: &IP_ADAPTER_ADDRESSES_LH) -> Status {
    match adapter_address.OperStatus {
        IfOperStatusUp => Status::Up,
        IfOperStatusDown => Status::Down,
        IfOperStatusTesting | IfOperStatusUnknown | IfOperStatusDormant | IfOperStatusNotPresent | IfOperStatusLowerLayerDown => Status::Unavailable,
        _ => Status::Unknown,
    }
}
/// map interface type to libc flags
/// reference https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
fn get_adapter_flags(adapter_address: &IP_ADAPTER_ADDRESSES_LH) -> i32 {
    match adapter_address.IfType {
        IF_TYPE_OTHER | IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE1394 => IFF_ETH,
        IF_TYPE_PPP | IF_TYPE_TUNNEL => IFF_TUN,
        IF_TYPE_IEEE80211 => IFF_WIRELESS,
        IF_TYPE_SOFTWARE_LOOPBACK => IFF_LOOPBACK,
        _ => 0,
    }
}

/// Trait for linked lists in Windows API structures iteration
trait IterableRawPointer {
    type Pointer;
    type Value;

    ///  Returns: pointer to the next element in the linked list
    ///           null at the end
    fn next(&self) -> Self::Pointer;
}

/// Raw pointer container
struct RawPointerWrapper<'a, T>(*const T, PhantomData<&'a T>)
where
    T: IterableRawPointer<Value = T, Pointer = *const T>;

impl<'a, T> RawPointerWrapper<'a, T>
where
    T: IterableRawPointer<Value = T, Pointer = *const T>,
{
    fn new(ptr: *const T) -> RawPointerWrapper<'a, T> {
        Self(ptr, PhantomData)
    }
}

/// Iterator implementation for RawPointer
impl<'a, T> Iterator for RawPointerWrapper<'a, T>
where
    T: IterableRawPointer<Value = T, Pointer = *const T>,
{
    type Item = &'a T::Value;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = unsafe { self.0.as_ref() };
        if let Some(v) = ret {
            self.0 = v.next();
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use std::{process::Command, cmp::min};

    use crate::{NetworkInterface, NetworkInterfaceConfig, Addr};

    #[test]
    fn test_mac_addr() {
        const MAC_ADDR_LEN: usize = "00:22:48:03:ED:76".len();

        let output = Command::new("getmac").arg("/nh").output().unwrap().stdout;
        let output_string = String::from_utf8(output).unwrap();
        let mac_addr_list: Vec<_> = output_string
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let line = &line[..min(MAC_ADDR_LEN, line.len())];
                match line.split('-').count() {
                    6 => Some(line.replace('-', ":")),
                    _ => None,
                }
            })
            .collect();
        assert!(!mac_addr_list.is_empty());

        let interfaces = NetworkInterface::show().unwrap();
        for mac_addr in mac_addr_list {
            assert!(interfaces
                .iter()
                .any(|int| int.mac_addr.as_ref() == Some(&mac_addr)));
        }
    }

    #[test]
    // Check IP address consistency.
    fn test_ipv4_broadcast() {
        let interfaces = NetworkInterface::show().unwrap();
        for ipv4 in interfaces.iter().flat_map(|i| &i.addr).filter_map(|addr| {
            if let Addr::V4(ipv4) = addr {
                Some(ipv4)
            } else {
                None
            }
        }) {
            let Some(bc_addr) = ipv4.broadcast else {
                continue;
            };
            let ip_bytes = ipv4.ip.octets();
            let mask_bytes = ipv4.netmask.unwrap().octets();
            let bc_bytes = bc_addr.octets();
            for i in 0..4 {
                assert_eq!(ip_bytes[i] & mask_bytes[i], bc_bytes[i] & mask_bytes[i]);
                assert_eq!(bc_bytes[i] | mask_bytes[i], 255);
            }
        }
    }
}
