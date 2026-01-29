using IcsThreatClassification.Domain.Enums;

namespace IcsThreatClassification.ClassicEngine.Rules;

/// <summary>
/// Фабрика для создания правил обнаружения угроз на основе шаблонов безопасности АСУ ТП.
/// Каждое правило объединяет несколько индикаторов признаков для надёжного обнаружения.
/// </summary>
internal static class ThreatRuleSet
{
    public static IReadOnlyList<ThreatRule> CreateRules()
    {
        return
        [
            CreateUnauthorizedRemoteAccessRule(),
            CreateMaliciousCommandInjectionRule(),
            CreateConfigurationTamperingRule(),
            CreateDenialOfServiceRule(),
            CreateRansomwareActivityRule(),
            CreateDataExfiltrationRule(),
            CreateManInTheMiddleRule(),
            CreateProtocolMisuseRule(),
            CreateBruteForceAuthenticationRule(),
            CreateSuspiciousEngineeringWorkstationRule()
        ];
    }

    private static ThreatRule CreateUnauthorizedRemoteAccessRule()
    {
        return new ThreatRule(
            IcsThreatType.UnauthorizedRemoteAccess,
            features =>
            {
                double score = 0.0;

                // Внешние подключения из необычных источников
                if (features.ExternalConnectionCount > 5)
                    score += 0.35 * Math.Min(features.ExternalConnectionCount / 10.0, 1.0);

                // Аномально высокий уровень зашифрованного трафика для OT
                if (features.EncryptedTrafficRatio > 0.4)
                    score += 0.30 * features.EncryptedTrafficRatio;

                // Высокий трафик к инженерным станциям
                if (features.TrafficToEngineeringStationsRatio > 0.3)
                    score += 0.25 * features.TrafficToEngineeringStationsRatio;

                // Неудачные попытки входа, указывающие на зондирование
                if (features.FailedLoginRate > 0.1)
                    score += 0.10 * features.FailedLoginRate;

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.ExternalConnectionCount > 5)
                    indicators.Add($"Внешних подключений: {features.ExternalConnectionCount}");
                if (features.EncryptedTrafficRatio > 0.4)
                    indicators.Add($"Доля зашифрованного трафика: {features.EncryptedTrafficRatio:P0}");
                if (features.TrafficToEngineeringStationsRatio > 0.3)
                    indicators.Add($"Трафик к инженерным станциям: {features.TrafficToEngineeringStationsRatio:P0}");
                if (features.FailedLoginRate > 0.1)
                    indicators.Add($"Доля неудачных входов: {features.FailedLoginRate:P0}");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateMaliciousCommandInjectionRule()
    {
        return new ThreatRule(
            IcsThreatType.MaliciousCommandInjection,
            features =>
            {
                double score = 0.0;

                // Подозрительные команды вне белого списка
                if (features.SuspiciousCommandCount > 2)
                    score += 0.40 * Math.Min(features.SuspiciousCommandCount / 10.0, 1.0);

                // Нарушения протокола, указывающие на искажённые команды
                if (features.ProtocolViolationScore > 0.3)
                    score += 0.30 * features.ProtocolViolationScore;

                // Высокая частота изменения конфигурации ПЛК
                if (features.PlcConfigChangeRate > 0.5)
                    score += 0.20 * features.PlcConfigChangeRate;

                // Аномалии параметров процесса из-за вредоносных команд
                if (features.ProcessValueAnomalyScore > 0.4)
                    score += 0.10 * features.ProcessValueAnomalyScore;

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.SuspiciousCommandCount > 2)
                    indicators.Add($"Подозрительных команд: {features.SuspiciousCommandCount}");
                if (features.ProtocolViolationScore > 0.3)
                    indicators.Add($"Нарушений протокола: {features.ProtocolViolationScore:F2}");
                if (features.PlcConfigChangeRate > 0.5)
                    indicators.Add($"Частота изменения конфигурации ПЛК: {features.PlcConfigChangeRate:F2}");
                if (features.ProcessValueAnomalyScore > 0.4)
                    indicators.Add($"Аномалия процесса: {features.ProcessValueAnomalyScore:F2}");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateConfigurationTamperingRule()
    {
        return new ThreatRule(
            IcsThreatType.ConfigurationTampering,
            features =>
            {
                double score = 0.0;

                // Высокая частота изменений конфигурации
                if (features.PlcConfigChangeRate > 0.6)
                    score += 0.35 * features.PlcConfigChangeRate;

                // Изменения экранов HMI, указывающие на несанкционированный доступ
                if (features.HmiScreenChangeRate > 0.5)
                    score += 0.25 * features.HmiScreenChangeRate;

                // Трафик к инженерным рабочим станциям
                if (features.TrafficToEngineeringStationsRatio > 0.4)
                    score += 0.25 * features.TrafficToEngineeringStationsRatio;

                // Нарушения протокола из-за искажённых команд конфигурации
                if (features.ProtocolViolationScore > 0.2)
                    score += 0.15 * features.ProtocolViolationScore;

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.PlcConfigChangeRate > 0.6)
                    indicators.Add($"Частота изменения конфигурации: {features.PlcConfigChangeRate:F2}");
                if (features.HmiScreenChangeRate > 0.5)
                    indicators.Add($"Изменений экранов HMI: {features.HmiScreenChangeRate:F2}");
                if (features.TrafficToEngineeringStationsRatio > 0.4)
                    indicators.Add($"Инженерный трафик: {features.TrafficToEngineeringStationsRatio:P0}");
                if (features.ProtocolViolationScore > 0.2)
                    indicators.Add($"Нарушений протокола: {features.ProtocolViolationScore:F2}");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateDenialOfServiceRule()
    {
        return new ThreatRule(
            IcsThreatType.DenialOfService,
            features =>
            {
                double score = 0.0;

                // Высокая частота подключений, указывающая на флуд
                if (features.ConnectionRate > 50)
                    score += 0.35 * Math.Min(features.ConnectionRate / 100.0, 1.0);

                // Высокая доля широковещательного трафика, указывающая на усиление
                if (features.BroadcastTrafficRatio > 0.5)
                    score += 0.30 * features.BroadcastTrafficRatio;

                // Аномалия ЦП из-за истощения ресурсов
                if (features.CpuLoadAnomalyScore > 0.6)
                    score += 0.25 * features.CpuLoadAnomalyScore;

                // Большие пакеты, потенциально для атак фрагментацией
                if (features.AveragePacketSize > 1200)
                    score += 0.10 * Math.Min((features.AveragePacketSize - 1200) / 300.0, 1.0);

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.ConnectionRate > 50)
                    indicators.Add($"Частота подключений: {features.ConnectionRate:F0}/с");
                if (features.BroadcastTrafficRatio > 0.5)
                    indicators.Add($"Доля широковещания: {features.BroadcastTrafficRatio:P0}");
                if (features.CpuLoadAnomalyScore > 0.6)
                    indicators.Add($"Аномалия ЦП: {features.CpuLoadAnomalyScore:F2}");
                if (features.AveragePacketSize > 1200)
                    indicators.Add($"Средний размер пакета: {features.AveragePacketSize:F0}Б");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateRansomwareActivityRule()
    {
        return new ThreatRule(
            IcsThreatType.RansomwareActivity,
            features =>
            {
                double score = 0.0;

                // Всплеск зашифрованного трафика (шифрование данных вымогателем)
                if (features.EncryptedTrafficRatio > 0.6)
                    score += 0.35 * features.EncryptedTrafficRatio;

                // Аномалия ЦП из-за операций шифрования
                if (features.CpuLoadAnomalyScore > 0.5)
                    score += 0.25 * features.CpuLoadAnomalyScore;

                // Внешние подключения для C2 или записок о выкупе
                if (features.ExternalConnectionCount > 3)
                    score += 0.25 * Math.Min(features.ExternalConnectionCount / 8.0, 1.0);

                // Активная запись/изменение данных
                if (features.DataExfiltrationVolume > 10)
                    score += 0.15 * Math.Min(features.DataExfiltrationVolume / 50.0, 1.0);

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.EncryptedTrafficRatio > 0.6)
                    indicators.Add($"Активность шифрования: {features.EncryptedTrafficRatio:P0}");
                if (features.CpuLoadAnomalyScore > 0.5)
                    indicators.Add($"Аномалия ЦП: {features.CpuLoadAnomalyScore:F2}");
                if (features.ExternalConnectionCount > 3)
                    indicators.Add($"Внешних подключений: {features.ExternalConnectionCount}");
                if (features.DataExfiltrationVolume > 10)
                    indicators.Add($"Объём данных: {features.DataExfiltrationVolume:F1}МБ");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateDataExfiltrationRule()
    {
        return new ThreatRule(
            IcsThreatType.DataExfiltration,
            features =>
            {
                double score = 0.0;

                // Большие объёмы исходящих данных
                if (features.DataExfiltrationVolume > 20)
                    score += 0.40 * Math.Min(features.DataExfiltrationVolume / 100.0, 1.0);

                // Внешние подключения как цели эксфильтрации
                if (features.ExternalConnectionCount > 2)
                    score += 0.25 * Math.Min(features.ExternalConnectionCount / 6.0, 1.0);

                // Зашифрованный трафик для сокрытия данных
                if (features.EncryptedTrafficRatio > 0.3)
                    score += 0.20 * features.EncryptedTrafficRatio;

                // Большие пакеты для массовой передачи
                if (features.AveragePacketSize > 800)
                    score += 0.15 * Math.Min((features.AveragePacketSize - 800) / 700.0, 1.0);

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.DataExfiltrationVolume > 20)
                    indicators.Add($"Объём исходящих данных: {features.DataExfiltrationVolume:F1}МБ");
                if (features.ExternalConnectionCount > 2)
                    indicators.Add($"Внешних целей: {features.ExternalConnectionCount}");
                if (features.EncryptedTrafficRatio > 0.3)
                    indicators.Add($"Доля зашифрованного: {features.EncryptedTrafficRatio:P0}");
                if (features.AveragePacketSize > 800)
                    indicators.Add($"Размер пакета: {features.AveragePacketSize:F0}Б");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateManInTheMiddleRule()
    {
        return new ThreatRule(
            IcsThreatType.ManInTheMiddle,
            features =>
            {
                double score = 0.0;

                // Нарушения протокола из-за внедрённых/изменённых пакетов
                if (features.ProtocolViolationScore > 0.4)
                    score += 0.35 * features.ProtocolViolationScore;

                // Широковещательный трафик для ARP-спуфинга
                if (features.BroadcastTrafficRatio > 0.4)
                    score += 0.25 * features.BroadcastTrafficRatio;

                // Множество протоколов, указывающих на ретрансляцию
                if (features.DistinctProtocolCount > 5)
                    score += 0.25 * Math.Min((features.DistinctProtocolCount - 5) / 5.0, 1.0);

                // Аномалии подключений
                if (features.ConnectionRate > 30)
                    score += 0.15 * Math.Min(features.ConnectionRate / 60.0, 1.0);

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.ProtocolViolationScore > 0.4)
                    indicators.Add($"Нарушений протокола: {features.ProtocolViolationScore:F2}");
                if (features.BroadcastTrafficRatio > 0.4)
                    indicators.Add($"Широковещательный трафик: {features.BroadcastTrafficRatio:P0}");
                if (features.DistinctProtocolCount > 5)
                    indicators.Add($"Разнообразие протоколов: {features.DistinctProtocolCount}");
                if (features.ConnectionRate > 30)
                    indicators.Add($"Частота подключений: {features.ConnectionRate:F0}/с");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateProtocolMisuseRule()
    {
        return new ThreatRule(
            IcsThreatType.ProtocolMisuse,
            features =>
            {
                double score = 0.0;

                // Прямой индикатор нарушения протокола
                if (features.ProtocolViolationScore > 0.5)
                    score += 0.40 * features.ProtocolViolationScore;

                // Подозрительные команды через злоупотребление протоколом
                if (features.SuspiciousCommandCount > 1)
                    score += 0.25 * Math.Min(features.SuspiciousCommandCount / 5.0, 1.0);

                // Аномальное сочетание протоколов
                if (features.DistinctProtocolCount > 6)
                    score += 0.20 * Math.Min((features.DistinctProtocolCount - 6) / 4.0, 1.0);

                // Необычные размеры пакетов для протоколов АСУ ТП
                if (features.AveragePacketSize < 50 || features.AveragePacketSize > 1000)
                    score += 0.15;

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.ProtocolViolationScore > 0.5)
                    indicators.Add($"Нарушений протокола: {features.ProtocolViolationScore:F2}");
                if (features.SuspiciousCommandCount > 1)
                    indicators.Add($"Подозрительных команд: {features.SuspiciousCommandCount}");
                if (features.DistinctProtocolCount > 6)
                    indicators.Add($"Необычное количество протоколов: {features.DistinctProtocolCount}");
                if (features.AveragePacketSize < 50 || features.AveragePacketSize > 1000)
                    indicators.Add($"Аномальный размер пакета: {features.AveragePacketSize:F0}Б");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateBruteForceAuthenticationRule()
    {
        return new ThreatRule(
            IcsThreatType.BruteForceAuthentication,
            features =>
            {
                double score = 0.0;

                // Высокая доля неудачных входов — основной индикатор
                if (features.FailedLoginRate > 0.3)
                    score += 0.45 * features.FailedLoginRate;

                // Высокая частота подключений из-за повторных попыток
                if (features.ConnectionRate > 20)
                    score += 0.25 * Math.Min(features.ConnectionRate / 50.0, 1.0);

                // Трафик к инженерным станциям как целям
                if (features.TrafficToEngineeringStationsRatio > 0.2)
                    score += 0.20 * features.TrafficToEngineeringStationsRatio;

                // Внешние источники, пытающиеся получить доступ
                if (features.ExternalConnectionCount > 1)
                    score += 0.10 * Math.Min(features.ExternalConnectionCount / 5.0, 1.0);

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.FailedLoginRate > 0.3)
                    indicators.Add($"Неудачных входов: {features.FailedLoginRate:P0}");
                if (features.ConnectionRate > 20)
                    indicators.Add($"Частота подключений: {features.ConnectionRate:F0}/с");
                if (features.TrafficToEngineeringStationsRatio > 0.2)
                    indicators.Add($"Инженерный трафик: {features.TrafficToEngineeringStationsRatio:P0}");
                if (features.ExternalConnectionCount > 1)
                    indicators.Add($"Внешних источников: {features.ExternalConnectionCount}");
                return indicators.ToArray();
            });
    }

    private static ThreatRule CreateSuspiciousEngineeringWorkstationRule()
    {
        return new ThreatRule(
            IcsThreatType.SuspiciousEngineeringWorkstationActivity,
            features =>
            {
                double score = 0.0;

                // Высокий трафик к/от инженерных станций
                if (features.TrafficToEngineeringStationsRatio > 0.5)
                    score += 0.35 * features.TrafficToEngineeringStationsRatio;

                // Изменения конфигурации с рабочей станции
                if (features.PlcConfigChangeRate > 0.4)
                    score += 0.25 * features.PlcConfigChangeRate;

                // Манипуляции с HMI
                if (features.HmiScreenChangeRate > 0.4)
                    score += 0.20 * features.HmiScreenChangeRate;

                // Внешняя связность с рабочей станции
                if (features.ExternalConnectionCount > 2)
                    score += 0.20 * Math.Min(features.ExternalConnectionCount / 5.0, 1.0);

                return Math.Min(score, 1.0);
            },
            features =>
            {
                var indicators = new List<string>();
                if (features.TrafficToEngineeringStationsRatio > 0.5)
                    indicators.Add($"Трафик рабочей станции: {features.TrafficToEngineeringStationsRatio:P0}");
                if (features.PlcConfigChangeRate > 0.4)
                    indicators.Add($"Изменений конфигурации: {features.PlcConfigChangeRate:F2}");
                if (features.HmiScreenChangeRate > 0.4)
                    indicators.Add($"Активность HMI: {features.HmiScreenChangeRate:F2}");
                if (features.ExternalConnectionCount > 2)
                    indicators.Add($"Внешних подключений: {features.ExternalConnectionCount}");
                return indicators.ToArray();
            });
    }
}
