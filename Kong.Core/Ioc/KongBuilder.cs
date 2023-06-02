using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

using WebApiClientCore.Implementations;

using WebApiClientCore;
using Kong.Core.Interface;

namespace Kong.Core.Ioc
{
    public interface IKongBuilder
    {
        /// <summary>
        /// 获取服务集合
        /// </summary>
        IServiceCollection Services { get; }
    }

    public class KongBuilder : IKongBuilder
    {
        /// <summary>
        /// 获取服务集合
        /// </summary>
        public IServiceCollection Services { get; }

        public KongBuilder(IServiceCollection services)
        {
            this.Services = services;
        }
    }

    public static class KongBuilderExtensions
    {
        public static IKongBuilder AddKong(this IServiceCollection services, IConfiguration configuration)
        {
            var section = configuration.GetSection(nameof(KongOptions));
            services.AddOptions<KongOptions>().Bind(section);
            var options = services.BuildServiceProvider().GetRequiredService<IOptionsMonitor<KongOptions>>();
            services.AddHttpApi(typeof(IKong), o =>
            {
                o.HttpHost = new Uri(options.CurrentValue.Endpoint);
                o.UseLogging = options.CurrentValue.UseLogging;
            });
            return new KongBuilder(services);
        }

        public static IKongBuilder AddKong(this IServiceCollection services, IConfiguration configuration, Action<KongOptions> configureOptions)
        {
            var section = configuration.GetSection(nameof(KongOptions));
            services.AddOptions<KongOptions>().Bind(section).Configure(configureOptions);
            var options = services.BuildServiceProvider().GetRequiredService<IOptionsMonitor<KongOptions>>();
            services.AddHttpApi(typeof(IKong), o =>
            {
                o.HttpHost = new Uri(options.CurrentValue.Endpoint);
                o.UseLogging = options.CurrentValue.UseLogging;
            });
            return new KongBuilder(services);
        }
    }
}
