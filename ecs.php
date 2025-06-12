<?php

declare(strict_types=1);

// ecs.php
use PHP_CodeSniffer\Standards\Generic\Sniffs\PHP\ForbiddenFunctionsSniff;
use PhpCsFixer\Fixer\ArrayNotation\ArraySyntaxFixer;
use PhpCsFixer\Fixer\Import\NoUnusedImportsFixer;
use PhpCsFixer\Fixer\Operator\NotOperatorWithSuccessorSpaceFixer;
use PhpCsFixer\Fixer\Phpdoc\GeneralPhpdocAnnotationRemoveFixer;
use PhpCsFixer\Fixer\Phpdoc\NoBlankLinesAfterPhpdocFixer;
use PhpCsFixer\Fixer\Phpdoc\NoEmptyPhpdocFixer;
use PhpCsFixer\Fixer\Phpdoc\NoSuperfluousPhpdocTagsFixer;
use PhpCsFixer\Fixer\Strict\DeclareStrictTypesFixer;
use Symplify\EasyCodingStandard\Config\ECSConfig;
use Symplify\EasyCodingStandard\ValueObject\Set\SetList;

return static function (ECSConfig $ecsConfig): void {
    // Parallel
    $ecsConfig->parallel();

    $ecsConfig->cacheDirectory('.ecs-cache');
    // Paths
    $ecsConfig->paths([
        __DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/ecs.php'
    ]);
    $ecsConfig->skip([
        __DIR__ . '/src/helpers/Mdi.php'
    ]);

    // A. full sets
    $ecsConfig->sets([SetList::PSR_12, SetList::SPACES]);

    $ecsConfig->rule(NotOperatorWithSuccessorSpaceFixer::class);
    $ecsConfig->rule(ArraySyntaxFixer::class);
    $ecsConfig->ruleWithConfiguration(GeneralPhpdocAnnotationRemoveFixer::class, [
        'annotations' => ['author', 'inheritdoc']
    ]);
    $ecsConfig->rule(NoBlankLinesAfterPhpdocFixer::class);
    $ecsConfig->ruleWithConfiguration(NoSuperfluousPhpdocTagsFixer::class, [
        'allow_mixed' => true
    ]);
    $ecsConfig->rule(NoEmptyPhpdocFixer::class);
    $ecsConfig->rule(NoUnusedImportsFixer::class);
    $ecsConfig->rule(DeclareStrictTypesFixer::class);
    //    $ecsConfig->rule(PhpdocAlignFixer::class);

    $ecsConfig->ruleWithConfiguration(ForbiddenFunctionsSniff::class, [
        'forbiddenFunctions' => [
            'passthru' => null,
            'var_dump' => null,
        ]
    ]);
    $ecsConfig->skip([
        NotOperatorWithSuccessorSpaceFixer::class,
        __DIR__ . '/src/modules/SurveyjsBackend/src/helpers/DutchPostalCodes.php',
        __DIR__ . '/tests/_support/_generated/*',
        ForbiddenFunctionsSniff::class => [
            'tests/**',
            'console/**'
        ]
    ]);

    //    $ecsConfig->skip([
    //        FinalClassFixer::class => [
    //            'tests/**'
    //        ]
    //    ]);
};
