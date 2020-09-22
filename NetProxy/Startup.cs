using System;
using System.Linq;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Collections;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Hangfire;
using Hangfire.Console;
using Hangfire.Heartbeat;
using Hangfire.RecurringJobAdmin;
using Hangfire.JobsLogger;
using Hangfire.Heartbeat.Server;
using Hangfire.Dashboard;
using Hangfire.MemoryStorage;

namespace NetProxy
{
    public class Startup
    {
        private IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging();

            services.AddHangfire(config =>
            {
                config.SetDataCompatibilityLevel(CompatibilityLevel.Version_170);
                config.UseSimpleAssemblyNameTypeSerializer();
                config.UseRecommendedSerializerSettings();
                config.UseMemoryStorage();
                config.UseConsole();
                config.UseHeartbeatPage(checkInterval: TimeSpan.FromSeconds(1));
                config.UseRecurringJobAdmin(typeof(Startup).Assembly);
                config.UseJobsLogger();
            });
            //// Add the processing server as IHostedService
            //services.AddHangfireServer();

            services.AddControllersWithViews();
        }

        public void Configure(
            IApplicationBuilder app,
            IWebHostEnvironment env,
            IRecurringJobManager recurringJobs)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints
                    .MapHangfireDashboard("/hangfire", options: new DashboardOptions
                    {
                        Authorization = new[]
                        {
                            new BasicAuthenticationFilter(new[]
                            {
                                new UserCredentials
                                {
                                    Username = Configuration["Hangfire:Dashboard:Authentication:Username"],
                                    Password = Configuration["Hangfire:Dashboard:Authentication:Password"]
                                }
                            })
                        }
                    });

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });

            app.UseHangfireServer(additionalProcesses: new[]
            {
                new ProcessMonitor(checkInterval: TimeSpan.FromSeconds(10))
            });

            recurringJobs.Trigger("SomeJob");
        }
    }

    public class BasicAuthenticationFilter : IDashboardAuthorizationFilter
    {
        public IEnumerable<UserCredentials> Users { get; }

        public BasicAuthenticationFilter(IEnumerable<UserCredentials> users)
        {
            Users = users;
        }

        public bool Authorize(DashboardContext dashboardContext)
        {
            var context = dashboardContext.GetHttpContext();

            string header = context.Request.Headers["Authorization"];

            if (string.IsNullOrWhiteSpace(header) == false)
            {
                var authValues = AuthenticationHeaderValue.Parse(header);

                if ("Basic".Equals(authValues.Scheme, StringComparison.InvariantCultureIgnoreCase))
                {
                    var parameter = Encoding.UTF8.GetString(Convert.FromBase64String(authValues.Parameter));
                    var parts = parameter.Split(':');

                    if (parts.Length > 1)
                    {
                        var username = parts[0];
                        var password = parts[1];

                        if (string.IsNullOrWhiteSpace(username) == false && string.IsNullOrWhiteSpace(password) == false)
                        {
                            return Users.Any(user => user.Validate(username, password)) || Challenge(context);
                        }
                    }
                }
            }

            return Challenge(context);
        }

        private static bool Challenge(HttpContext context)
        {
            context.Response.StatusCode = 401;
            context.Response.Headers.Append("WWW-Authenticate", "Basic realm=\"Hangfire Dashboard\"");

            context.Response.WriteAsync("Authentication is required.");

            return false;
        }
    }

    public class UserCredentials
    {
        public string Username { get; set; }

        public byte[] PasswordSha1Hash { get; set; }

        public string Password
        {
            set
            {
                using var cryptoProvider = SHA1.Create();
                PasswordSha1Hash = cryptoProvider.ComputeHash(Encoding.UTF8.GetBytes(value));
            }
        }

        public bool Validate(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) == true)
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (string.IsNullOrWhiteSpace(password) == true)
            {
                throw new ArgumentNullException(nameof(password));
            }

            if (username == Username)
            {
                using var cryptoProvider = SHA1.Create();
                var passwordHash = cryptoProvider.ComputeHash(Encoding.UTF8.GetBytes(password));
                return StructuralComparisons.StructuralEqualityComparer.Equals(passwordHash, PasswordSha1Hash);
            }
            else
            {
                return false;
            }
        }
    }
}
