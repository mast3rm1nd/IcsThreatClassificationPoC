using Microsoft.ML.Data;

namespace IcsThreatClassification.MlEngine.Training;

/// <summary>
/// Класс входных данных ML.NET для обучения.
/// </summary>
internal sealed class MlTrainingData
{
    [LoadColumn(0)]
    public float AveragePacketSize { get; set; }

    [LoadColumn(1)]
    public float SuspiciousCommandCount { get; set; }

    [LoadColumn(2)]
    public float FailedLoginRate { get; set; }

    [LoadColumn(3)]
    public float TrafficToEngineeringStationsRatio { get; set; }

    [LoadColumn(4)]
    public float PlcConfigChangeRate { get; set; }

    [LoadColumn(5)]
    public float HmiScreenChangeRate { get; set; }

    [LoadColumn(6)]
    public float EncryptedTrafficRatio { get; set; }

    [LoadColumn(7)]
    public float ExternalConnectionCount { get; set; }

    [LoadColumn(8)]
    public float BroadcastTrafficRatio { get; set; }

    [LoadColumn(9)]
    public float ProtocolViolationScore { get; set; }

    [LoadColumn(10)]
    public float DataExfiltrationVolume { get; set; }

    [LoadColumn(11)]
    public float CpuLoadAnomalyScore { get; set; }

    [LoadColumn(12)]
    public float ProcessValueAnomalyScore { get; set; }

    [LoadColumn(13)]
    public float ConnectionRate { get; set; }

    [LoadColumn(14)]
    public float DistinctProtocolCount { get; set; }

    [LoadColumn(15)]
    public uint Label { get; set; }
}
