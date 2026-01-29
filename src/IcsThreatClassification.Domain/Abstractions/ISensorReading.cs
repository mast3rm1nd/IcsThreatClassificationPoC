using IcsThreatClassification.Domain.ValueObjects;

namespace IcsThreatClassification.Domain.Abstractions;

/// <summary>
/// Абстракция для данных чтения сенсора.
/// </summary>
public interface ISensorReading
{
    DateTimeOffset Timestamp { get; }
    SensorId SensorId { get; }
    SensorFeatureVector Features { get; }
}
