using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Enums;
using Spectre.Console;

namespace IcsThreatClassification.App.Commands;

/// <summary>
/// Обработчик команды для генерации синтетических данных и обучения ML-модели.
/// </summary>
internal sealed class GenerateAndTrainCommand
{
    private readonly ISyntheticDatasetGenerator _datasetGenerator;
    private readonly IThreatModelTrainer _modelTrainer;

    public GenerateAndTrainCommand(
        ISyntheticDatasetGenerator datasetGenerator,
        IThreatModelTrainer modelTrainer)
    {
        _datasetGenerator = datasetGenerator;
        _modelTrainer = modelTrainer;
    }

    public void Execute(int samplesPerType, string modelPath, bool useGpu)
    {
        AnsiConsole.MarkupLine("[bold]Генерация синтетического набора данных...[/]");

        var datasetOptions = new SyntheticDatasetOptions
        {
            SamplesPerThreatType = samplesPerType,
            Seed = 42
        };

        var dataset = _datasetGenerator.Generate(datasetOptions);

        DisplayDatasetStatistics(dataset, samplesPerType);

        AnsiConsole.MarkupLine("\n[bold]Обучение ML-модели...[/]");

        var trainingOptions = new ThreatModelTrainingOptions
        {
            NumberOfIterations = 100,
            UseGpu = useGpu,
            Seed = 42
        };

        AnsiConsole.Status()
            .Start("Выполняется обучение...", ctx =>
            {
                ctx.Spinner(Spinner.Known.Dots);
                _modelTrainer.Train(dataset, trainingOptions);
            });

        AnsiConsole.MarkupLine("[green]Обучение завершено.[/]");

        _modelTrainer.Save(modelPath);
        AnsiConsole.MarkupLine($"[green]Модель сохранена в:[/] {modelPath}");
    }

    private static void DisplayDatasetStatistics(
        IReadOnlyCollection<Domain.Models.LabeledSensorSample> dataset,
        int samplesPerType)
    {
        var threatTypes = Enum.GetValues<IcsThreatType>();

        var table = new Table();
        table.AddColumn("Тип угрозы");
        table.AddColumn("Количество образцов");

        int totalSamples = 0;
        foreach (var threatType in threatTypes)
        {
            int count = dataset.Count(s => s.Label == threatType);
            totalSamples += count;
            table.AddRow(threatType.ToString(), count.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        table.AddRow("[bold]Всего[/]", $"[bold]{totalSamples}[/]");

        AnsiConsole.Write(table);
    }
}
