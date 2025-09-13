using System.Runtime.InteropServices;

internal static class TaricFfi
{
    [DllImport("taric_server")]
    internal static extern int taric_server_start(string configJson);

    [DllImport("taric_server")]
    internal static extern int taric_server_stop();
}
