namespace IcsThreatClassification.Domain.Enums;

/// <summary>
/// Типы угроз, специфичные для промышленных систем управления (АСУ ТП) и SCADA-сетей.
/// </summary>
public enum IcsThreatType
{
    /// <summary>
    /// Нормальный трафик, угрозы не обнаружены.
    /// </summary>
    None = 0,

    /// <summary>
    /// Попытки несанкционированного удалённого доступа к компонентам АСУ ТП.
    /// </summary>
    UnauthorizedRemoteAccess = 1,

    /// <summary>
    /// Внедрение вредоносных команд в ПЛК, RTU или другие полевые устройства.
    /// </summary>
    MaliciousCommandInjection = 2,

    /// <summary>
    /// Несанкционированное изменение конфигурации устройств или прошивки.
    /// </summary>
    ConfigurationTampering = 3,

    /// <summary>
    /// Атаки отказа в обслуживании, направленные на доступность OT-сети.
    /// </summary>
    DenialOfService = 4,

    /// <summary>
    /// Активность программ-вымогателей или криптолокеров в сегменте OT-сети.
    /// </summary>
    RansomwareActivity = 5,

    /// <summary>
    /// Эксфильтрация конфиденциальных операционных данных или данных процесса.
    /// </summary>
    DataExfiltration = 6,

    /// <summary>
    /// Атаки типа "человек посередине", перехватывающие или изменяющие OT-трафик.
    /// </summary>
    ManInTheMiddle = 7,

    /// <summary>
    /// Неправильное использование или аномальное использование промышленных протоколов (Modbus, OPC UA, DNP3 и т.д.).
    /// </summary>
    ProtocolMisuse = 8,

    /// <summary>
    /// Попытки подбора паролей против механизмов аутентификации.
    /// </summary>
    BruteForceAuthentication = 9,

    /// <summary>
    /// Подозрительная активность с инженерных рабочих станций или ноутбуков обслуживания.
    /// </summary>
    SuspiciousEngineeringWorkstationActivity = 10
}
