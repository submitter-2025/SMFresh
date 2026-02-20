#!/bin/bash

TARGET=$1
LOG_FILE="${TARGET}.log"

QUERIES=("3n3e" "5n4e" "5n6e" "5n7e" "6n6e" "6n8e")
SCALES=(20000 40000 80000 160000 320000 640000 1280000 2560000)

DEFAULT_ROUNDS=10
DEFAULT_INTERVAL=1
DEFAULT_BATCH=5000
DEFAULT_TS=20

case $TARGET in
    "fig6")
        GDB_NAMES=("Email" "DBLP" "Youtube" "Patents" "Wiki" "Synthetic")
        for db in 0 1 2; do
            for q in "${QUERIES[@]}"; do
                CUR_DB=${GDB_NAMES[$db]}
                echo "==============================================================================" | tee -a $LOG_FILE
                echo "[META] DATASET_IDX=$db DATASET_NAME=$CUR_DB QUERY=$q BATCH=$DEFAULT_BATCH TS=$DEFAULT_TS" | tee -a $LOG_FILE
                echo ">> [START] Experiment: DB=$CUR_DB ($db), Query=$q" | tee -a $LOG_FILE

                python Main.py \
                --dataset $db \
                --init_ratio 1.0 \
                --batch_size $DEFAULT_BATCH \
                --ts_size $DEFAULT_TS \
                --query $q \
                --rounds $DEFAULT_ROUNDS \
                --interval $DEFAULT_INTERVAL >> $LOG_FILE 2>&1

                echo ">> [END] Finished $CUR_DB - $q" | tee -a $LOG_FILE
                echo "" | tee -a $LOG_FILE
            done
        done
        ;;

    "fig7")
        CUR_DB="Patents"
        for s in "${SCALES[@]}"; do
            for q in "5n7e" "6n8e"; do
                echo "==============================================================================" | tee -a $LOG_FILE
                echo "[META] DATASET_IDX=3 DATASET_NAME=$CUR_DB SCALE=$s QUERY=$q BATCH=$DEFAULT_BATCH TS=$DEFAULT_TS" | tee -a $LOG_FILE
                echo ">> [START] Experiment: $CUR_DB (Scale=$s), Query=$q" | tee -a $LOG_FILE

                python Main.py \
                --dataset 3 \
                --init_ratio 1.0 \
                --scale $s \
                --batch_size $DEFAULT_BATCH \
                --ts_size $DEFAULT_TS \
                --query $q \
                --rounds $DEFAULT_ROUNDS \
                --interval $DEFAULT_INTERVAL >> $LOG_FILE 2>&1

                echo ">> [END] Finished Scale=$s - Query=$q" | tee -a $LOG_FILE
                echo "" | tee -a $LOG_FILE
            done
        done
        ;;

    "fig10")
        CUR_DB="Wiki-Talk"
        FIXED_Q_SIZE=100

        BATCHES_A=(500 1000 2000 5000 10000 20000 40000 80000 160000 320000)
        TS_SIZES_B=(10 20 50 100 200 500 1000 2000 3000 4000)
        Q_SIZES_C=(10 20 50 100 200 500 1000 2000 3000 4000)
        BATCHES_D=(5000 10000 20000 50000 100000 200000 500000 1000000)

        for b in "${BATCHES_A[@]}"; do
            echo "==============================================================================" | tee -a $LOG_FILE
            echo "[META] EXP=fig10a DATASET_NAME=$CUR_DB VARIABLE=BATCH_SIZE VALUE=$b FIXED_QUERY=$FIXED_Q_SIZE FIXED_TS=$DEFAULT_TS" | tee -a $LOG_FILE
            echo ">> [START] (a) Vary Update Size: Batch=$b" | tee -a $LOG_FILE

            python Main.py \
            --dataset 4 \
            --init_ratio 0.5 \
            --batch_size $b \
            --ts_size $DEFAULT_TS \
            --query $FIXED_Q_SIZE \
            --rounds $DEFAULT_ROUNDS \
            --interval $DEFAULT_INTERVAL >> $LOG_FILE 2>&1

            echo ">> [END] Finished Batch=$b" | tee -a $LOG_FILE
            echo "" | tee -a $LOG_FILE
        done

        for ts in "${TS_SIZES_B[@]}"; do
            echo "==============================================================================" | tee -a $LOG_FILE
            echo "[META] EXP=fig10b DATASET_NAME=$CUR_DB VARIABLE=TS_SIZE VALUE=$ts FIXED_BATCH=$DEFAULT_BATCH FIXED_QUERY=$FIXED_Q_SIZE" | tee -a $LOG_FILE
            echo ">> [START] (b) Vary TS Size: TS=$ts" | tee -a $LOG_FILE

            python Main.py \
            --dataset 4 \
            --init_ratio 0.5 \
            --batch_size $DEFAULT_BATCH \
            --ts_size $ts \
            --query $FIXED_Q_SIZE \
            --rounds $DEFAULT_ROUNDS \
            --interval $DEFAULT_INTERVAL >> $LOG_FILE 2>&1

            echo ">> [END] Finished TS=$ts" | tee -a $LOG_FILE
            echo "" | tee -a $LOG_FILE
        done

        for qs in "${Q_SIZES_C[@]}"; do
            echo "==============================================================================" | tee -a $LOG_FILE
            echo "[META] EXP=fig10c DATASET_NAME=$CUR_DB VARIABLE=QUERY_SIZE VALUE=$qs FIXED_BATCH=$DEFAULT_BATCH FIXED_TS=$DEFAULT_TS" | tee -a $LOG_FILE
            echo ">> [START] (c) Vary Query Size: QuerySize=$qs" | tee -a $LOG_FILE

            python Main.py \
            --dataset 4 \
            --init_ratio 0.5 \
            --batch_size $DEFAULT_BATCH \
            --ts_size $DEFAULT_TS \
            --query $qs \
            --rounds $DEFAULT_ROUNDS \
            --interval $DEFAULT_INTERVAL >> $LOG_FILE 2>&1

            echo ">> [END] Finished QuerySize=$qs" | tee -a $LOG_FILE
            echo "" | tee -a $LOG_FILE
        done

        TOTAL_UPDATES=1000000

        for lb in "${BATCHES_D[@]}"; do
            CUR_ROUNDS=$((TOTAL_UPDATES / lb))
            echo "==============================================================================" | tee -a $LOG_FILE
            echo "[META] EXP=fig10d DATASET_NAME=$CUR_DB VARIABLE=BATCH_SIZE_FIXED_TOTAL VALUE=$lb TOTAL_UPDATES=$TOTAL_UPDATES ROUNDS=$CUR_ROUNDS FIXED_QUERY=$FIXED_Q_SIZE" | tee -a $LOG_FILE
            echo ">> [START] (d) Fixed Total 1M: Batch=$lb * Rounds=$CUR_ROUNDS" | tee -a $LOG_FILE

            python Main.py \
            --dataset 4 \
            --init_ratio 0.5 \
            --batch_size $lb \
            --ts_size $DEFAULT_TS \
            --query $FIXED_Q_SIZE \
            --rounds $CUR_ROUNDS \
            --interval $CUR_ROUNDS \
            >> $LOG_FILE 2>&1

            echo ">> [END] Finished FixedTotal Batch=$lb" | tee -a $LOG_FILE
            echo "" | tee -a $LOG_FILE
        done
        ;;

    "fig11")
        CUR_DB="Synthetic"
        FIXED_Q_SIZE=100

        BATCHES_A=(500 1000 2000 5000 10000 20000 40000 80000 160000 320000)
        TS_SIZES_B=(10 20 50 100 200 500 1000 2000 3000 4000)
        Q_SIZES_C=(10 20 50 100 200 500 1000 2000 3000 4000)
        BATCHES_D=(5000 10000 20000 50000 100000 200000 500000 1000000)

        for b in "${BATCHES_A[@]}"; do
            echo "==============================================================================" | tee -a $LOG_FILE
            echo "[META] EXP=fig11a DATASET_NAME=$CUR_DB VARIABLE=BATCH_SIZE VALUE=$b FIXED_QUERY=$FIXED_Q_SIZE FIXED_TS=$DEFAULT_TS" | tee -a $LOG_FILE
            echo ">> [START] (a) Vary Update Size: Batch=$b" | tee -a $LOG_FILE

            python Main.py \
            --dataset 5 \
            --init_ratio 1.0 \
            --batch_size $b \
            --ts_size $DEFAULT_TS \
            --query $FIXED_Q_SIZE \
            --rounds $DEFAULT_ROUNDS \
            --interval $DEFAULT_INTERVAL \
            >> $LOG_FILE 2>&1

            echo ">> [END] Finished Batch=$b" | tee -a $LOG_FILE
            echo "" | tee -a $LOG_FILE
        done

        for ts in "${TS_SIZES_B[@]}"; do
            echo "==============================================================================" | tee -a $LOG_FILE
            echo "[META] EXP=fig11b DATASET_NAME=$CUR_DB VARIABLE=TS_SIZE VALUE=$ts FIXED_BATCH=$DEFAULT_BATCH FIXED_QUERY=$FIXED_Q_SIZE" | tee -a $LOG_FILE
            echo ">> [START] (b) Vary TS Size: TS=$ts" | tee -a $LOG_FILE

            python Main.py \
            --dataset 5 \
            --init_ratio 1.0 \
            --batch_size $DEFAULT_BATCH \
            --ts_size $ts \
            --query $FIXED_Q_SIZE \
            --rounds $DEFAULT_ROUNDS \
            --interval $DEFAULT_INTERVAL \
            >> $LOG_FILE 2>&1

            echo ">> [END] Finished TS=$ts" | tee -a $LOG_FILE
            echo "" | tee -a $LOG_FILE
        done

        for qs in "${Q_SIZES_C[@]}"; do
            echo "==============================================================================" | tee -a $LOG_FILE
            echo "[META] EXP=fig11c DATASET_NAME=$CUR_DB VARIABLE=QUERY_SIZE VALUE=$qs FIXED_BATCH=$DEFAULT_BATCH FIXED_TS=$DEFAULT_TS" | tee -a $LOG_FILE
            echo ">> [START] (c) Vary Query Size: QuerySize=$qs" | tee -a $LOG_FILE

            python Main.py \
            --dataset 5 \
            --init_ratio 1.0 \
            --batch_size $DEFAULT_BATCH \
            --ts_size $DEFAULT_TS \
            --query $qs \
            --rounds $DEFAULT_ROUNDS \
            --interval $DEFAULT_INTERVAL \
            >> $LOG_FILE 2>&1

            echo ">> [END] Finished QuerySize=$qs" | tee -a $LOG_FILE
            echo "" | tee -a $LOG_FILE
        done

        TOTAL_UPDATES=1000000

        for lb in "${BATCHES_D[@]}"; do
            CUR_ROUNDS=$((TOTAL_UPDATES / lb))
            echo "==============================================================================" | tee -a $LOG_FILE
            echo "[META] EXP=fig11d DATASET_NAME=$CUR_DB VARIABLE=BATCH_SIZE_FIXED_TOTAL VALUE=$lb TOTAL_UPDATES=$TOTAL_UPDATES ROUNDS=$CUR_ROUNDS FIXED_QUERY=$FIXED_Q_SIZE" | tee -a $LOG_FILE
            echo ">> [START] (d) Fixed Total 1M: Batch=$lb * Rounds=$CUR_ROUNDS" | tee -a $LOG_FILE

            python Main.py \
            --dataset 5 \
            --init_ratio 1.0 \
            --batch_size $lb \
            --ts_size $DEFAULT_TS \
            --query $FIXED_Q_SIZE \
            --rounds $CUR_ROUNDS \
            --interval $CUR_ROUNDS \
            >> $LOG_FILE 2>&1

            echo ">> [END] Finished FixedTotal Batch=$lb" | tee -a $LOG_FILE
            echo "" | tee -a $LOG_FILE
        done
        ;;
esac