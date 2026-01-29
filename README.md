# Система классификации угроз АСУ ТП

Прототип системы сетевого мониторинга (NTA) для обнаружения угроз в промышленных системах управления (АСУ ТП/SCADA). Решение демонстрирует многоуровневый подход к классификации угроз с использованием как классических правил, так и машинного обучения.

## Архитектура

Решение следует принципам Clean Architecture с чётким разделением ответственности:

```
IcsThreatClassification/
├── src/
│   ├── IcsThreatClassification.Domain/        # Доменные сущности, value objects, интерфейсы
│   ├── IcsThreatClassification.ClassicEngine/ # Классификатор на основе правил
│   ├── IcsThreatClassification.MlEngine/      # ML-классификатор с обучением
│   └── IcsThreatClassification.App/           # Консольное приложение
└── tests/
    └── IcsThreatClassification.Tests/         # Unit и интеграционные тесты
```

### Доменный слой

Содержит основные доменные сущности и абстракции:
- `SensorReading` - образец трафика с вектором признаков
- `SensorFeatureVector` - 15 признаков, описывающих поведение сети и процессов
- `ThreatClassificationResult` - результат классификации с уверенностью и объяснением
- `IcsThreatType` - 10 типов угроз, специфичных для АСУ ТП, плюс нормальный трафик

### Классический движок

Классификатор на основе правил с предопределёнными правилами обнаружения. Каждый тип угрозы определяется комбинацией минимум 3 признаков с настраиваемыми порогами и функциями оценки.

### ML-движок

Классификатор на основе машинного обучения с использованием ML.NET:
- `SyntheticDatasetGenerator` - генерирует размеченные обучающие данные с реалистичными распределениями признаков
- `ThreatClassificationTrainer` - обучает модели многоклассовой классификации (SDCA или LightGBM)
- `MlThreatClassifier` - выполняет инференс с использованием обученных моделей

## Типы угроз

Система обнаруживает следующие угрозы, специфичные для АСУ ТП:

| Тип угрозы | Ключевые индикаторы |
|------------|---------------------|
| UnauthorizedRemoteAccess | Внешние подключения, зашифрованный трафик, трафик к инженерным станциям |
| MaliciousCommandInjection | Подозрительные команды, нарушения протокола, изменения конфигурации ПЛК |
| ConfigurationTampering | Скорость изменений конфигурации, активность HMI, трафик к инженерным станциям |
| DenialOfService | Частота подключений, широковещательный трафик, аномалии CPU |
| RansomwareActivity | Зашифрованный трафик, нагрузка CPU, внешние подключения |
| DataExfiltration | Исходящий объём, внешние подключения, размер пакетов |
| ManInTheMiddle | Нарушения протокола, широковещательный трафик, разнообразие протоколов |
| ProtocolMisuse | Нарушения протокола, подозрительные команды, аномальные размеры пакетов |
| BruteForceAuthentication | Процент неудачных входов, частота подключений, трафик к инженерным станциям |
| SuspiciousEngineeringWorkstationActivity | Трафик инженерных станций, изменения конфигурации, активность HMI |

## Требования

- .NET 8.0 SDK
- Windows, Linux или macOS

## Сборка

```bash
dotnet restore
dotnet build
```

## Запуск тестов

```bash
dotnet test
```

## Использование

### Генерация данных и обучение модели

```bash
cd src/IcsThreatClassification.App
dotnet run -- generate-and-train --samples 500 --model-path model/threat_classifier.zip
```

Опции:
- `--samples` - количество образцов на каждый тип угрозы (по умолчанию: 500)
- `--model-path` - путь для сохранения обученной модели (по умолчанию: model/threat_classifier.zip)
- `--use-gpu` - включить ускорение GPU для обучения (по умолчанию: false)

<img width="799" height="495" alt="Image" src="https://github.com/user-attachments/assets/c2682ff7-eb18-4dc7-9d18-fac9c5dc6c29" />

### Классификация образцов

```bash
dotnet run -- classify-sample --model-path model/threat_classifier.zip
```

Эта команда:
1. Загружает обученную ML-модель
2. Генерирует тестовые образцы для каждого типа угрозы
3. Классифицирует с использованием классического и ML-классификаторов
4. Выводит сравнительную таблицу с результатами

<img width="1455" height="1213" alt="Image" src="https://github.com/user-attachments/assets/237f8a9d-f659-4d09-a558-01b28a8e0e8b" />

## Вектор признаков

Каждое чтение с сенсора содержит 15 признаков:

| Признак | Описание | Диапазон |
|---------|----------|----------|
| AveragePacketSize | Средний размер пакета в байтах | 10-1500 |
| SuspiciousCommandCount | Команды вне белого списка | 0+ |
| FailedLoginRate | Процент неудачных аутентификаций | 0-1 |
| TrafficToEngineeringStationsRatio | Трафик к инженерным станциям | 0-1 |
| PlcConfigChangeRate | Скорость изменений конфигурации ПЛК | 0-1 |
| HmiScreenChangeRate | Скорость изменений экранов HMI | 0-1 |
| EncryptedTrafficRatio | Доля зашифрованного трафика | 0-1 |
| ExternalConnectionCount | Подключения к внешним IP | 0+ |
| BroadcastTrafficRatio | Доля широковещательного трафика | 0-1 |
| ProtocolViolationScore | Оценка искажений протокола | 0-1 |
| DataExfiltrationVolume | Объём исходящих данных (МБ) | 0+ |
| CpuLoadAnomalyScore | Аномалия нагрузки CPU | 0-1 |
| ProcessValueAnomalyScore | Аномалия значений процесса | 0-1 |
| ConnectionRate | Новых подключений в секунду | 0+ |
| DistinctProtocolCount | Количество различных протоколов | 1+ |

## Dependency Injection

Сервисы регистрируются через методы расширения:

```csharp
services.AddClassicThreatClassifier();  // IClassicThreatClassifier
services.AddMlThreatClassifier();       // IMlThreatClassifier, IThreatModelTrainer, ISyntheticDatasetGenerator
```

## Обучение ML-модели

ML-конвейер:
1. Конкатенация всех 15 признаков
2. Применение MinMax-нормализации
3. Преобразование меток в ключи
4. Обучение с использованием SDCA (CPU) или LightGBM (GPU)
5. Обратное преобразование предсказаний в типы угроз

Модели сохраняются в формате ZIP ML.NET и могут быть загружены для инференса без переобучения.

## Лицензия

Это прототип/демонстрационный проект для исследований в области безопасности АСУ ТП.
