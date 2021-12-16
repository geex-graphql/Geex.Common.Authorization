using System.Security.Claims;
using System.Threading.Tasks;

using Geex.Common.Identity.Core.Aggregates.Users;

namespace Geex.Common.Authentication
{
    public interface ISubClaimsTransformation
    {
        Task<ClaimsPrincipal> TransformAsync(User user, ClaimsPrincipal claimsPrincipal);
    }
}