using System;
using System.Collections.Generic;
using System.Text;

namespace Kong.Core.Models
{
    public class ConfigRequest
    {
        public string Message { get; set; }
    }

    public class ConfigResponse
    {
        public List<string> Services { get; set; }
        public List<string> Routes { get; set; }
    }
}
