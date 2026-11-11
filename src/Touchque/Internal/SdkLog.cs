using Microsoft.Extensions.Logging;

namespace Touchque.Internal;

/// <summary>
/// The SDK's own problems (a misconfigured guard, a failed OnChallenge, a relay without
/// GetLoginUser): to <see cref="TouchqueOptions.Logger"/>, to Console.Error with
/// <see cref="TouchqueOptions.Debug"/>, else nowhere. A logger that throws never breaks a request.
/// </summary>
internal sealed class SdkLog
{
    private readonly ILogger? _logger;
    private readonly bool _debug;

    public SdkLog(ILogger? logger, bool debug)
    {
        _logger = logger;
        _debug = debug;
    }

    public void Warn(string message) => Write(LogLevel.Warning, message);

    public void Error(string message) => Write(LogLevel.Error, message);

    /// <summary><c>Type: message</c> for a log line: never the request it came from.</summary>
    public static string Describe(Exception e) => e.GetType().Name + ": " + e.Message;

    private void Write(LogLevel level, string message)
    {
        try
        {
            if (_logger is not null) _logger.Log(level, "{Message}", message);
            else if (_debug) Console.Error.WriteLine(message);
        }
        catch (Exception)
        {
            // a logger must never break a request
        }
    }
}
