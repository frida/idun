using Efni;

namespace Idun {
	/**
	 * The ICE transport a call's media rides on: it gathers the local candidates a peer
	 * can reach us at, takes the peer's in return, runs the connectivity checks that
	 * pick a working path between them, and once that path is up carries the RTP packets
	 * each way.
	 */
	public sealed class IceAgent : Object {
		private Nice.Agent agent;
		private uint stream_id;

		private const uint COMPONENT = 1;

		public signal void gathered ();
		public signal void connected ();
		public signal void received (uint8[] data);

		public IceAgent (bool controlling) {
			var ctx = MainContext.ref_thread_default ();
			agent = new Nice.Agent (ctx, Nice.Compatibility.RFC5245);
			agent.controlling_mode = controlling;

			stream_id = agent.add_stream (1);
			agent.attach_recv (stream_id, COMPONENT, ctx, on_received);
			agent.candidate_gathering_done.connect (on_gathered);
			agent.component_state_changed.connect (on_state_changed);
		}

		public void gather () {
			agent.gather_candidates (stream_id);
		}

		public string local_description () {
			return agent.generate_local_sdp ();
		}

		public void set_remote_description (string description) {
			agent.parse_remote_sdp (description);
		}

		public void send (uint8[] packet) {
			agent.send (stream_id, COMPONENT, packet.length, (string) packet);
		}

		private void on_received (Nice.Agent agent, uint stream_id, uint component_id, uint8[] data) {
			received (data);
		}

		private void on_gathered (uint stream_id) {
			gathered ();
		}

		private void on_state_changed (uint stream_id, uint component_id, Nice.ComponentState state) {
			if (state == Nice.ComponentState.READY)
				connected ();
		}
	}
}
