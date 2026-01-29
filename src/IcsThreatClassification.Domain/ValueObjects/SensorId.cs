namespace IcsThreatClassification.Domain.ValueObjects;

/// <summary>
/// Уникальный идентификатор сенсора в инфраструктуре мониторинга.
/// </summary>
public sealed record SensorId
{
    public string Value { get; }

    public SensorId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Идентификатор сенсора не может быть пустым.", nameof(value));
        }

        Value = value;
    }

    public static SensorId Create(string value) => new(value);

    public static SensorId NewId() => new(Guid.NewGuid().ToString("N"));

    public override string ToString() => Value;

    public static implicit operator string(SensorId id) => id.Value;
}
