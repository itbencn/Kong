using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

using WebApiClientCore;
using WebApiClientCore.Attributes;

namespace Kong.Core
{
    [AttributeUsage(AttributeTargets.Interface | AttributeTargets.Method)]
    public class KongLoggingFilterAttribute : LoggingFilterAttribute
    {

    }
}
