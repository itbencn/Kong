using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kong.Test
{
    public class ConsoleService : IHostedService
    {
        public ILogger<ConsoleService> logger { get; set; }
        public IKong kong { get; set; }
        public KongOptions kongOptions { get; set; }
        public ConsoleService(ILogger<ConsoleService> logger, IKong kong, IOptionsMonitor<KongOptions> kongOptions)
        {
            this.logger = logger;
            this.kong = kong;
            this.kongOptions = kongOptions.CurrentValue;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            //logger.LogInformation($"kongOptions Endpoint={kongOptions.Endpoint} UseLogging={kongOptions.UseLogging}");


            //await kong.ConfigAsync();

            await kong.RootAsync();



        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
        }
    }
}
