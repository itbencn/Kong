using Kong.Core;
using Kong.Core.Ioc;

namespace Kong.Example
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            //var s=builder.Services.AddWebApiClient();

            //builder.Services.AddKong(builder.Configuration, t =>
            //{
            //    System.Diagnostics.Debug.WriteLine($"KongOptions {t.Endpoint} - {t.UseLogging}");
            //    t.Endpoint = "http://www.qq.com";
            //    t.UseLogging = true;
            //});

            builder.Services.AddKong(builder.Configuration);

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}