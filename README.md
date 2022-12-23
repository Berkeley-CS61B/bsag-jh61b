# `jh61b` for BSAG

Steps for running `jh61b.jar` with BSAG.

## Notice

**This package is currently under active development! It's probably broken.**
I'm working as fast as I can to un-break it and add features.
Once I've verified that I can run an autograder, I will publish it on PyPI.

## Usage

`jh61b` uses "pieces", which are a related group of test files. Each piece
is defined by the set of student files and assessment files it depends on.

An example set of `jh61b` steps might look like

```yaml
# Check that the relevant files are present
- jh61b.check_files:
      pieces:
          TestIntList:
              # Student files must be present and not clobbered by AG files
              student_files:
                  - IntList/IntListExercises.java
                  - IntList/IntList.java
                  - IntList/Primes.java
              # jh61b test files that will be run later.
              assessment_files:
                  - AGTestAddConstant.java
                  - AGTestSetToZeroIfMaxFEL.java
                  - AGTestSquarePrimes.java
          # Define multiple pieces that can succeed or fail independently
          TestArithmetic:
              student_files:
                  - Arithmetic/Arithmetic.java
              assessment_files:
                  - AGTestArithmetic.java
          TestDebugExercise:
              student_files:
                  - DebugExercise/DebugExercise2.java
              assessment_files:
                  - AGTestDebugExercise.java
# Compile every piece
- jh61b.compilation
# use `jdeps` to verify that studnet files don't depend on disallowed libraries
# for example, `reflect` can be used to fake behavior under test.
- jh61b.dep_check:
      disallowed_classes:
          - java.lang.reflect.**
# Run the assessments.
# These are currently separate steps because they produce individual logs.
- jh61b.assessment:
      piece_name: TestIntList
- jh61b.assessment:
      piece_name: TestArithmetic
# This test requires students to pass every test in the file(s) to receive
# full credit. The aggregation report has gradescope test number "3".
- jh61b.assessment:
      piece_name: TestDebugExercise
      require_full_score: true
      aggregated_number: 3
# Weight module scores to achieve a total score.
- jh61b.final_score:
      scoring:
          TestIntList: 80
          TestArithmetic: 16
          TestDebugExercise: 32
      max_points: 128
```
