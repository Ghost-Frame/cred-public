using Yubico.YubiKey;
using Yubico.YubiKey.Otp;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: ykchallenge <challenge_hex>");
    Console.Error.WriteLine("       ykchallenge program <secret_hex>");
    return 1;
}

var devices = YubiKeyDevice.FindAll();
var device = devices.FirstOrDefault();
if (device is null)
{
    Console.Error.WriteLine("error: no YubiKey found");
    return 1;
}

// Program mode: ykchallenge program <secret_hex>
if (args[0] == "program")
{
    if (args.Length != 2)
    {
        Console.Error.WriteLine("usage: ykchallenge program <secret_hex_40chars>");
        return 1;
    }

    byte[] secret;
    try
    {
        secret = Convert.FromHexString(args[1]);
    }
    catch (FormatException)
    {
        Console.Error.WriteLine("error: secret must be a hex string");
        return 1;
    }

    if (secret.Length != 20)
    {
        Console.Error.WriteLine($"error: HMAC-SHA1 secret must be exactly 20 bytes (got {secret.Length})");
        return 1;
    }

    try
    {
        using var otp = new OtpSession(device);
        otp.ConfigureChallengeResponse(Slot.LongPress)
            .UseHmacSha1()
            .UseKey(secret)
            .UseSmallChallenge()
            .UseButton(false)
            .Execute();

        Console.Error.WriteLine("programmed slot 2 (LongPress) with HMAC-SHA1 secret");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"error: {ex.Message}");
        return 1;
    }
}

// Challenge mode: ykchallenge <challenge_hex>
byte[] challenge;
try
{
    challenge = Convert.FromHexString(args[0]);
}
catch (FormatException)
{
    Console.Error.WriteLine("error: challenge must be a hex string");
    return 1;
}

try
{
    using var otp = new OtpSession(device);
    ReadOnlyMemory<byte> response = otp.CalculateChallengeResponse(Slot.LongPress)
        .UseChallenge(challenge)
        .UseYubiOtp(false)
        .UseTouchNotifier(() => Console.Error.WriteLine("touch yubikey..."))
        .GetDataBytes();

    if (response.Length != 20)
    {
        Console.Error.WriteLine($"error: unexpected HMAC-SHA1 response length {response.Length} (expected 20 bytes)");
        return 1;
    }

    Console.WriteLine(Convert.ToHexString(response.ToArray()).ToLower());
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}
