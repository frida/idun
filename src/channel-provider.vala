namespace Idun {
	public interface ChannelProvider : Object {
		public abstract async IOStream open_channel (string address, Cancellable? cancellable = null) throws Efni.Error, IOError;
	}
}
