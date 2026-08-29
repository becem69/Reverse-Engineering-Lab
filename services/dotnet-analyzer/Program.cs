var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    var port = int.Parse(Environment.GetEnvironmentVariable("GRPC_PORT") ?? "50057");
    options.ListenAnyIP(port, o => o.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2);
});
builder.Services.AddGrpc();

var app = builder.Build();
app.MapGrpcService<Malwarelab.AnalyzerService>();

app.Run();
