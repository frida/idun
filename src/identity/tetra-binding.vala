using Efni;

namespace Idun {
	/**
	 * One party's routing in a pair-tetra message's authenticated data: the handle it
	 * is addressed by, the push token that reaches it, and the device signing key that
	 * identifies it. Binding these into the signature stops a message being rerouted.
	 */
	public sealed class TetraBinding : Object {
		public Bytes handle {
			get;
			construct;
		}

		public Bytes push_token {
			get;
			construct;
		}

		public Bytes device_key {
			get;
			construct;
		}

		public TetraBinding (Bytes handle, Bytes push_token, Bytes device_key) {
			Object (handle: handle, push_token: push_token, device_key: device_key);
		}
	}
}
