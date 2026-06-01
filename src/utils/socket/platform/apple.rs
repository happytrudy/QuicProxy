use std::io;

use tracing::warn;

use crate::utils::interface::InterfaceInfo;
use crate::utils::interface::InterfaceInfoExt;
use crate::utils::new_io_other_error;

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &InterfaceInfo,
    family: socket2::Domain,
) -> io::Result<()> {
    let index = iface.index;
    if index == 0 {
        warn!(
            "OutboundInterface index is 0, skipping binding to interface {}",
            iface.display_name()
        );
        return Ok(());
    }
    match family {
        socket2::Domain::IPV4 => socket.bind_device_by_index_v4(std::num::NonZeroU32::new(index)),
        socket2::Domain::IPV6 => socket.bind_device_by_index_v6(std::num::NonZeroU32::new(index)),
        _ => Err(new_io_other_error("unsupported socket family")),
    }
}
