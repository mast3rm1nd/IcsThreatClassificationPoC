using System.CommandLine;
using IcsThreatClassification.App.Commands;
using IcsThreatClassification.ClassicEngine;
using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.MlEngine;
using IcsThreatClassification.MlEngine.Inference;
using IcsThreatClassification.MlEngine.Training;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console;

namespace IcsThreatClassification.App;

internal static class Program
{
    private const string DefaultModelPath = "model/threat_classifier.zip";

    public static async Task<int> Main(string[] args)
    {
        var services = ConfigureServices();

        var rootCommand = new RootCommand("Система классификации угроз АСУ ТП - прототип NTA");

        var generateAndTrainCommand = CreateGenerateAndTrainCommand(services);
        var classifySampleCommand = CreateClassifySampleCommand(services);

        rootCommand.AddCommand(generateAndTrainCommand);
        rootCommand.AddCommand(classifySampleCommand);

        if (args.Length == 0)
        {
            PrintBanner();
            AnsiConsole.MarkupLine("Используйте [bold]--help[/] для просмотра доступных команд.");
            return 0;
        }

        return await rootCommand.InvokeAsync(args);
    }

    private static ServiceProvider ConfigureServices()
    {
        var services = new ServiceCollection();

        services.AddClassicThreatClassifier();
        services.AddMlThreatClassifier();

        return services.BuildServiceProvider();
    }

    private static Command CreateGenerateAndTrainCommand(IServiceProvider services)
    {
        var samplesOption = new Option<int>(
            name: "--samples",
            description: "Количество образцов на тип угрозы",
            getDefaultValue: () => 500);

        var modelPathOption = new Option<string>(
            name: "--model-path",
            description: "Путь для сохранения обученной модели",
            getDefaultValue: () => DefaultModelPath);

        var useGpuOption = new Option<bool>(
            name: "--use-gpu",
            description: "Использовать GPU для обучения, если доступен",
            getDefaultValue: () => false);

        var command = new Command("generate-and-train", "Сгенерировать синтетический набор данных и обучить ML-модель")
        {
            samplesOption,
            modelPathOption,
            useGpuOption
        };

        command.SetHandler((samples, modelPath, useGpu) =>
        {
            var generator = services.GetRequiredService<ISyntheticDatasetGenerator>();
            var trainer = services.GetRequiredService<IThreatModelTrainer>();

            var handler = new GenerateAndTrainCommand(generator, trainer);
            handler.Execute(samples, modelPath, useGpu);
        }, samplesOption, modelPathOption, useGpuOption);

        return command;
    }

    private static Command CreateClassifySampleCommand(IServiceProvider services)
    {
        var modelPathOption = new Option<string>(
            name: "--model-path",
            description: "Путь к обученной модели",
            getDefaultValue: () => DefaultModelPath);

        var command = new Command("classify-sample", "Классифицировать образцы с использованием обоих классификаторов")
        {
            modelPathOption
        };

        command.SetHandler(modelPath =>
        {
            var classicClassifier = services.GetRequiredService<IClassicThreatClassifier>();
            var mlClassifier = services.GetRequiredService<MlThreatClassifier>();
            var trainer = services.GetRequiredService<ThreatClassificationTrainer>();
            var generator = services.GetRequiredService<ISyntheticDatasetGenerator>();

            var handler = new ClassifySampleCommand(classicClassifier, mlClassifier, trainer, generator);
            handler.Execute(modelPath);
        }, modelPathOption);

        return command;
    }

    private static void PrintBanner()
    {
        var rule = new Rule("[bold blue]Система классификации угроз АСУ ТП[/]");
        AnsiConsole.Write(rule);

        AnsiConsole.MarkupLine("\n[dim]Прототип анализатора сетевого трафика для промышленных систем управления[/]");
        AnsiConsole.MarkupLine("[dim]Поддерживает классификацию угроз на основе правил и ML[/]\n");
    }
}
