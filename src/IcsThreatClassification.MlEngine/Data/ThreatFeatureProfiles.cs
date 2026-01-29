using IcsThreatClassification.Domain.Enums;

namespace IcsThreatClassification.MlEngine.Data;

/// <summary>
/// Профили распределения признаков для каждого типа угрозы.
/// Определяет средние значения и стандартные отклонения для генерации синтетических данных.
/// </summary>
internal static class ThreatFeatureProfiles
{
    /// <summary>
    /// Возвращает профиль признаков (среднее, стандартное отклонение) для заданного типа угрозы.
    /// </summary>
    public static FeatureProfile GetProfile(IcsThreatType threatType)
    {
        return threatType switch
        {
            IcsThreatType.UnauthorizedRemoteAccess => CreateUnauthorizedRemoteAccessProfile(),
            IcsThreatType.MaliciousCommandInjection => CreateMaliciousCommandInjectionProfile(),
            IcsThreatType.ConfigurationTampering => CreateConfigurationTamperingProfile(),
            IcsThreatType.DenialOfService => CreateDenialOfServiceProfile(),
            IcsThreatType.RansomwareActivity => CreateRansomwareActivityProfile(),
            IcsThreatType.DataExfiltration => CreateDataExfiltrationProfile(),
            IcsThreatType.ManInTheMiddle => CreateManInTheMiddleProfile(),
            IcsThreatType.ProtocolMisuse => CreateProtocolMisuseProfile(),
            IcsThreatType.BruteForceAuthentication => CreateBruteForceAuthenticationProfile(),
            IcsThreatType.SuspiciousEngineeringWorkstationActivity => CreateSuspiciousEngineeringProfile(),
            IcsThreatType.None => CreateNormalTrafficProfile(),
            _ => throw new ArgumentOutOfRangeException(nameof(threatType))
        };
    }

    private static FeatureProfile CreateUnauthorizedRemoteAccessProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (400f, 100f),
            SuspiciousCommandCount = (1f, 1f),
            FailedLoginRate = (0.25f, 0.1f),
            TrafficToEngineeringStationsRatio = (0.55f, 0.15f),
            PlcConfigChangeRate = (0.1f, 0.05f),
            HmiScreenChangeRate = (0.15f, 0.05f),
            EncryptedTrafficRatio = (0.65f, 0.15f),
            ExternalConnectionCount = (12f, 4f),
            BroadcastTrafficRatio = (0.1f, 0.05f),
            ProtocolViolationScore = (0.15f, 0.08f),
            DataExfiltrationVolume = (5f, 3f),
            CpuLoadAnomalyScore = (0.2f, 0.1f),
            ProcessValueAnomalyScore = (0.1f, 0.05f),
            ConnectionRate = (15f, 8f),
            DistinctProtocolCount = (4f, 1f)
        };
    }

    private static FeatureProfile CreateMaliciousCommandInjectionProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (180f, 50f),
            SuspiciousCommandCount = (15f, 5f),
            FailedLoginRate = (0.05f, 0.03f),
            TrafficToEngineeringStationsRatio = (0.2f, 0.1f),
            PlcConfigChangeRate = (0.7f, 0.15f),
            HmiScreenChangeRate = (0.25f, 0.1f),
            EncryptedTrafficRatio = (0.1f, 0.05f),
            ExternalConnectionCount = (1f, 1f),
            BroadcastTrafficRatio = (0.05f, 0.03f),
            ProtocolViolationScore = (0.6f, 0.15f),
            DataExfiltrationVolume = (1f, 0.5f),
            CpuLoadAnomalyScore = (0.3f, 0.1f),
            ProcessValueAnomalyScore = (0.65f, 0.15f),
            ConnectionRate = (8f, 4f),
            DistinctProtocolCount = (3f, 1f)
        };
    }

    private static FeatureProfile CreateConfigurationTamperingProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (350f, 80f),
            SuspiciousCommandCount = (3f, 2f),
            FailedLoginRate = (0.1f, 0.05f),
            TrafficToEngineeringStationsRatio = (0.65f, 0.12f),
            PlcConfigChangeRate = (0.85f, 0.1f),
            HmiScreenChangeRate = (0.7f, 0.15f),
            EncryptedTrafficRatio = (0.2f, 0.1f),
            ExternalConnectionCount = (2f, 1f),
            BroadcastTrafficRatio = (0.08f, 0.04f),
            ProtocolViolationScore = (0.35f, 0.12f),
            DataExfiltrationVolume = (3f, 2f),
            CpuLoadAnomalyScore = (0.25f, 0.1f),
            ProcessValueAnomalyScore = (0.4f, 0.15f),
            ConnectionRate = (12f, 5f),
            DistinctProtocolCount = (4f, 1f)
        };
    }

    private static FeatureProfile CreateDenialOfServiceProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (1350f, 150f),
            SuspiciousCommandCount = (2f, 1f),
            FailedLoginRate = (0.15f, 0.08f),
            TrafficToEngineeringStationsRatio = (0.1f, 0.05f),
            PlcConfigChangeRate = (0.05f, 0.03f),
            HmiScreenChangeRate = (0.05f, 0.03f),
            EncryptedTrafficRatio = (0.15f, 0.08f),
            ExternalConnectionCount = (5f, 3f),
            BroadcastTrafficRatio = (0.75f, 0.12f),
            ProtocolViolationScore = (0.3f, 0.15f),
            DataExfiltrationVolume = (2f, 1f),
            CpuLoadAnomalyScore = (0.85f, 0.1f),
            ProcessValueAnomalyScore = (0.5f, 0.2f),
            ConnectionRate = (120f, 30f),
            DistinctProtocolCount = (3f, 1f)
        };
    }

    private static FeatureProfile CreateRansomwareActivityProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (600f, 150f),
            SuspiciousCommandCount = (4f, 2f),
            FailedLoginRate = (0.08f, 0.04f),
            TrafficToEngineeringStationsRatio = (0.25f, 0.1f),
            PlcConfigChangeRate = (0.15f, 0.08f),
            HmiScreenChangeRate = (0.2f, 0.1f),
            EncryptedTrafficRatio = (0.85f, 0.08f),
            ExternalConnectionCount = (8f, 3f),
            BroadcastTrafficRatio = (0.12f, 0.06f),
            ProtocolViolationScore = (0.25f, 0.1f),
            DataExfiltrationVolume = (35f, 15f),
            CpuLoadAnomalyScore = (0.75f, 0.12f),
            ProcessValueAnomalyScore = (0.35f, 0.15f),
            ConnectionRate = (25f, 10f),
            DistinctProtocolCount = (5f, 2f)
        };
    }

    private static FeatureProfile CreateDataExfiltrationProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (1100f, 200f),
            SuspiciousCommandCount = (1f, 1f),
            FailedLoginRate = (0.05f, 0.03f),
            TrafficToEngineeringStationsRatio = (0.15f, 0.08f),
            PlcConfigChangeRate = (0.08f, 0.04f),
            HmiScreenChangeRate = (0.1f, 0.05f),
            EncryptedTrafficRatio = (0.55f, 0.15f),
            ExternalConnectionCount = (9f, 3f),
            BroadcastTrafficRatio = (0.05f, 0.03f),
            ProtocolViolationScore = (0.15f, 0.08f),
            DataExfiltrationVolume = (80f, 25f),
            CpuLoadAnomalyScore = (0.3f, 0.12f),
            ProcessValueAnomalyScore = (0.15f, 0.08f),
            ConnectionRate = (18f, 8f),
            DistinctProtocolCount = (4f, 1f)
        };
    }

    private static FeatureProfile CreateManInTheMiddleProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (280f, 80f),
            SuspiciousCommandCount = (2f, 1f),
            FailedLoginRate = (0.12f, 0.06f),
            TrafficToEngineeringStationsRatio = (0.2f, 0.08f),
            PlcConfigChangeRate = (0.1f, 0.05f),
            HmiScreenChangeRate = (0.12f, 0.06f),
            EncryptedTrafficRatio = (0.3f, 0.12f),
            ExternalConnectionCount = (3f, 2f),
            BroadcastTrafficRatio = (0.65f, 0.12f),
            ProtocolViolationScore = (0.7f, 0.12f),
            DataExfiltrationVolume = (8f, 4f),
            CpuLoadAnomalyScore = (0.2f, 0.1f),
            ProcessValueAnomalyScore = (0.25f, 0.1f),
            ConnectionRate = (55f, 15f),
            DistinctProtocolCount = (9f, 2f)
        };
    }

    private static FeatureProfile CreateProtocolMisuseProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (35f, 15f),
            SuspiciousCommandCount = (6f, 3f),
            FailedLoginRate = (0.08f, 0.04f),
            TrafficToEngineeringStationsRatio = (0.15f, 0.08f),
            PlcConfigChangeRate = (0.2f, 0.1f),
            HmiScreenChangeRate = (0.15f, 0.08f),
            EncryptedTrafficRatio = (0.08f, 0.04f),
            ExternalConnectionCount = (1f, 1f),
            BroadcastTrafficRatio = (0.2f, 0.1f),
            ProtocolViolationScore = (0.85f, 0.08f),
            DataExfiltrationVolume = (2f, 1f),
            CpuLoadAnomalyScore = (0.15f, 0.08f),
            ProcessValueAnomalyScore = (0.2f, 0.1f),
            ConnectionRate = (10f, 5f),
            DistinctProtocolCount = (10f, 2f)
        };
    }

    private static FeatureProfile CreateBruteForceAuthenticationProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (150f, 40f),
            SuspiciousCommandCount = (1f, 1f),
            FailedLoginRate = (0.75f, 0.12f),
            TrafficToEngineeringStationsRatio = (0.45f, 0.15f),
            PlcConfigChangeRate = (0.05f, 0.03f),
            HmiScreenChangeRate = (0.08f, 0.04f),
            EncryptedTrafficRatio = (0.25f, 0.1f),
            ExternalConnectionCount = (4f, 2f),
            BroadcastTrafficRatio = (0.08f, 0.04f),
            ProtocolViolationScore = (0.1f, 0.05f),
            DataExfiltrationVolume = (1f, 0.5f),
            CpuLoadAnomalyScore = (0.2f, 0.1f),
            ProcessValueAnomalyScore = (0.1f, 0.05f),
            ConnectionRate = (65f, 20f),
            DistinctProtocolCount = (2f, 1f)
        };
    }

    private static FeatureProfile CreateSuspiciousEngineeringProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (450f, 100f),
            SuspiciousCommandCount = (2f, 1f),
            FailedLoginRate = (0.1f, 0.05f),
            TrafficToEngineeringStationsRatio = (0.8f, 0.1f),
            PlcConfigChangeRate = (0.65f, 0.15f),
            HmiScreenChangeRate = (0.7f, 0.12f),
            EncryptedTrafficRatio = (0.35f, 0.12f),
            ExternalConnectionCount = (6f, 2f),
            BroadcastTrafficRatio = (0.1f, 0.05f),
            ProtocolViolationScore = (0.2f, 0.1f),
            DataExfiltrationVolume = (12f, 5f),
            CpuLoadAnomalyScore = (0.35f, 0.12f),
            ProcessValueAnomalyScore = (0.3f, 0.12f),
            ConnectionRate = (20f, 8f),
            DistinctProtocolCount = (5f, 1f)
        };
    }

    private static FeatureProfile CreateNormalTrafficProfile()
    {
        return new FeatureProfile
        {
            AveragePacketSize = (250f, 50f),
            SuspiciousCommandCount = (0f, 0.5f),
            FailedLoginRate = (0.02f, 0.01f),
            TrafficToEngineeringStationsRatio = (0.08f, 0.03f),
            PlcConfigChangeRate = (0.05f, 0.02f),
            HmiScreenChangeRate = (0.08f, 0.03f),
            EncryptedTrafficRatio = (0.05f, 0.02f),
            ExternalConnectionCount = (0f, 0.5f),
            BroadcastTrafficRatio = (0.1f, 0.03f),
            ProtocolViolationScore = (0.02f, 0.01f),
            DataExfiltrationVolume = (0.5f, 0.3f),
            CpuLoadAnomalyScore = (0.05f, 0.02f),
            ProcessValueAnomalyScore = (0.05f, 0.02f),
            ConnectionRate = (5f, 2f),
            DistinctProtocolCount = (3f, 1f)
        };
    }
}

/// <summary>
/// Профиль распределения признаков со средним значением и стандартным отклонением для каждого признака.
/// </summary>
internal sealed class FeatureProfile
{
    public (float Mean, float StdDev) AveragePacketSize { get; init; }
    public (float Mean, float StdDev) SuspiciousCommandCount { get; init; }
    public (float Mean, float StdDev) FailedLoginRate { get; init; }
    public (float Mean, float StdDev) TrafficToEngineeringStationsRatio { get; init; }
    public (float Mean, float StdDev) PlcConfigChangeRate { get; init; }
    public (float Mean, float StdDev) HmiScreenChangeRate { get; init; }
    public (float Mean, float StdDev) EncryptedTrafficRatio { get; init; }
    public (float Mean, float StdDev) ExternalConnectionCount { get; init; }
    public (float Mean, float StdDev) BroadcastTrafficRatio { get; init; }
    public (float Mean, float StdDev) ProtocolViolationScore { get; init; }
    public (float Mean, float StdDev) DataExfiltrationVolume { get; init; }
    public (float Mean, float StdDev) CpuLoadAnomalyScore { get; init; }
    public (float Mean, float StdDev) ProcessValueAnomalyScore { get; init; }
    public (float Mean, float StdDev) ConnectionRate { get; init; }
    public (float Mean, float StdDev) DistinctProtocolCount { get; init; }
}
