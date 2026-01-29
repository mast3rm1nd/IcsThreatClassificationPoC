using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.Domain.ValueObjects;

namespace IcsThreatClassification.Domain.Entities;

/// <summary>
/// Представляет сенсор, развёрнутый в инфраструктуре сети АСУ ТП.
/// </summary>
public sealed class Sensor
{
    public SensorId Id { get; }
    public string Location { get; }
    public SensorType Type { get; }

    public Sensor(SensorId id, string location, SensorType type)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Location = !string.IsNullOrWhiteSpace(location)
            ? location
            : throw new ArgumentException("Местоположение не может быть пустым.", nameof(location));
        Type = type;
    }

    public static Sensor Create(string location, SensorType type)
    {
        return new Sensor(SensorId.NewId(), location, type);
    }
}
