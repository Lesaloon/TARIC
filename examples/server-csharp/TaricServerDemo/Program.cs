Console.WriteLine("TARIC C# server demo (FFI).");
var rc = TaricFfi.taric_server_start("{\"bind\":\"127.0.0.1:8080\"}");
Console.WriteLine($"server_start rc={rc}. Press ENTER to stop.");
Console.ReadLine();
TaricFfi.taric_server_stop();
