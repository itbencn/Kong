global using Kong.Core;
global using Kong.Core.Ioc;
global using Kong.Core.Models;
global using Kong.Core.Interface;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Kong.Test
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var builder = Host.CreateDefaultBuilder(args);

            builder.ConfigureServices((context, services) =>
            {
                services.AddKong(context.Configuration, t =>
                {
                    t.Endpoint = "https://kong.itben.cn";
                    t.UseLogging = true;
                });
                services.AddHostedService<ConsoleService>();
            });

            var host = builder.Build();
            host.Run();
        }
    }
}