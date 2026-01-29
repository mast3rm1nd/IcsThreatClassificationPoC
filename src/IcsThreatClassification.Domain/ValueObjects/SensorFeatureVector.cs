namespace IcsThreatClassification.Domain.ValueObjects;

/// <summary>
/// Вектор признаков, извлечённый из трафика сенсора для классификации угроз.
/// Все признаки нормализованы или представляют значимые метрики для анализа трафика АСУ ТП.
/// </summary>
public sealed record SensorFeatureVector
{
    /// <summary>
    /// Средний размер пакета в байтах за период наблюдения.
    /// </summary>
    public float AveragePacketSize { get; init; }

    /// <summary>
    /// Количество команд вне разрешённого белого списка, отправленных ПЛК/RTU.
    /// </summary>
    public int SuspiciousCommandCount { get; init; }

    /// <summary>
    /// Процент неудачных попыток входа (от 0.0 до 1.0).
    /// </summary>
    public float FailedLoginRate { get; init; }

    /// <summary>
    /// Доля трафика, направленного на инженерные рабочие станции (от 0.0 до 1.0).
    /// </summary>
    public float TrafficToEngineeringStationsRatio { get; init; }

    /// <summary>
    /// Частота изменений конфигурации ПЛК за период наблюдения.
    /// </summary>
    public float PlcConfigChangeRate { get; init; }

    /// <summary>
    /// Частота изменений экранов HMI за период наблюдения.
    /// </summary>
    public float HmiScreenChangeRate { get; init; }

    /// <summary>
    /// Доля зашифрованного трафика в сегменте OT (от 0.0 до 1.0).
    /// Высокие значения подозрительны в типичных OT-средах.
    /// </summary>
    public float EncryptedTrafficRatio { get; init; }

    /// <summary>
    /// Количество подключений к внешним IP-адресам.
    /// </summary>
    public int ExternalConnectionCount { get; init; }

    /// <summary>
    /// Доля широковещательного трафика (от 0.0 до 1.0).
    /// </summary>
    public float BroadcastTrafficRatio { get; init; }

    /// <summary>
    /// Оценка, указывающая на нарушения протокола (искажения Modbus, OPC, DNP3).
    /// </summary>
    public float ProtocolViolationScore { get; init; }

    /// <summary>
    /// Объём исходящих данных к необычным адресатам (МБ).
    /// </summary>
    public float DataExfiltrationVolume { get; init; }

    /// <summary>
    /// Оценка аномалии паттернов загрузки CPU.
    /// </summary>
    public float CpuLoadAnomalyScore { get; init; }

    /// <summary>
    /// Оценка аномалии отклонения значений процесса.
    /// </summary>
    public float ProcessValueAnomalyScore { get; init; }

    /// <summary>
    /// Частота новых подключений в секунду.
    /// </summary>
    public float ConnectionRate { get; init; }

    /// <summary>
    /// Количество наблюдаемых различных типов протоколов.
    /// </summary>
    public int DistinctProtocolCount { get; init; }

    /// <summary>
    /// Возвращает значения признаков в виде массива для обработки ML.
    /// </summary>
    public float[] ToArray()
    {
        return
        [
            AveragePacketSize,
            SuspiciousCommandCount,
            FailedLoginRate,
            TrafficToEngineeringStationsRatio,
            PlcConfigChangeRate,
            HmiScreenChangeRate,
            EncryptedTrafficRatio,
            ExternalConnectionCount,
            BroadcastTrafficRatio,
            ProtocolViolationScore,
            DataExfiltrationVolume,
            CpuLoadAnomalyScore,
            ProcessValueAnomalyScore,
            ConnectionRate,
            DistinctProtocolCount
        ];
    }

    /// <summary>
    /// Имена признаков для ML-конвейера и логирования.
    /// </summary>
    public static string[] FeatureNames =>
    [
        nameof(AveragePacketSize),
        nameof(SuspiciousCommandCount),
        nameof(FailedLoginRate),
        nameof(TrafficToEngineeringStationsRatio),
        nameof(PlcConfigChangeRate),
        nameof(HmiScreenChangeRate),
        nameof(EncryptedTrafficRatio),
        nameof(ExternalConnectionCount),
        nameof(BroadcastTrafficRatio),
        nameof(ProtocolViolationScore),
        nameof(DataExfiltrationVolume),
        nameof(CpuLoadAnomalyScore),
        nameof(ProcessValueAnomalyScore),
        nameof(ConnectionRate),
        nameof(DistinctProtocolCount)
    ];

    public static int FeatureCount => 15;
}
