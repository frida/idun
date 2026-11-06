namespace Idun {
	public delegate void DatagramsHandler (Gee.Collection<Bytes> datagrams);

	public interface VirtualNetworkStack : NetworkStack {
		public signal void outgoing_datagrams (Gee.Collection<Bytes> datagrams);

		public static VirtualNetworkStack create (Bytes? ethernet_address, InetAddress? ipv6_address, uint16 mtu) {
#if LINUX
			try {
				return new TunNetworkStack (ethernet_address, ipv6_address, mtu);
			} catch (Efni.Error e) {
			}
#endif
			return new LwipNetworkStack (ethernet_address, ipv6_address, mtu);
		}

		public abstract void handle_incoming_datagrams (Gee.Collection<Bytes> datagrams) throws Efni.Error;

		public abstract void set_outgoing_datagrams_handler (owned DatagramsHandler? handler);

		public abstract void stop ();
	}
}
