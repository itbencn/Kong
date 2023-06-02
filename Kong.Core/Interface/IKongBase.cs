using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using Kong.Core.Models;
using WebApiClientCore.Attributes;

using WebApiClientCore;

namespace Kong.Core.Interface
{
    [KongLoggingFilter]
    public partial interface IKong
    {
        [JsonReturn]
        [HttpGet("")]
        ITask<RootResponse> RootAsync(CancellationToken cancellationToken = default);
    }
}
