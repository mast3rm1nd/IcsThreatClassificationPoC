using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.Domain.ValueObjects;

namespace IcsThreatClassification.Domain.Entities;

/// <summary>
/// Представляет образец трафика, захваченный сенсором в течение окна наблюдения.
/// </summary>
public sealed class SensorReading : ISensorReading
{
    public DateTimeOffset Timestamp { get; }
    public SensorId SensorId { get; }
    public SensorFeatureVector Features { get; }

    public SensorReading(DateTimeOffset timestamp, SensorId sensorId, SensorFeatureVector features)
    {
        Timestamp = timestamp;
        SensorId = sensorId ?? throw new ArgumentNullException(nameof(sensorId));
        Features = features ?? throw new ArgumentNullException(nameof(features));
    }

    public static SensorReading Create(SensorId sensorId, SensorFeatureVector features)
    {
        return new SensorReading(DateTimeOffset.UtcNow, sensorId, features);
    }
}
