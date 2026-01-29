namespace IcsThreatClassification.Domain.Enums;

/// <summary>
/// Типы сенсоров, развёрнутых в инфраструктуре мониторинга сети АСУ ТП.
/// </summary>
public enum SensorType
{
    /// <summary>
    /// Сетевой отвод, обеспечивающий пассивное зеркалирование трафика.
    /// </summary>
    NetworkTap,

    /// <summary>
    /// Монитор связи ПЛК, захватывающий логику лестничных диаграмм и данные процесса.
    /// </summary>
    PlcMonitor,

    /// <summary>
    /// Монитор активности экранов HMI и команд.
    /// </summary>
    HmiMonitor,

    /// <summary>
    /// Анализатор SCADA-протоколов (Modbus, DNP3, OPC UA).
    /// </summary>
    ScadaProtocolAnalyzer,

    /// <summary>
    /// Сенсор межсетевого экрана или IDS на границе OT/IT.
    /// </summary>
    BoundarySensor,

    /// <summary>
    /// Монитор активности инженерной рабочей станции.
    /// </summary>
    EngineeringWorkstationMonitor
}
