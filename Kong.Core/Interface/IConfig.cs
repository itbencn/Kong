using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

using WebApiClientCore.Attributes;
using WebApiClientCore.HttpContents;
using Kong.Core.Models;
using WebApiClientCore;

namespace Kong.Core.Interface
{
    public partial interface IKong
    {
        [JsonReturn]
        [HttpGet("config")]
        ITask<ConfigResponse> ConfigAsync(CancellationToken cancellationToken = default);
    }
}
