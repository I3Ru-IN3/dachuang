import pandas as pd
from sklearn.model_selection import train_test_split
import os
import argparse

def split_train_test(input_file, train_ratio=0.7, random_state=1):
    """
    将数据集分割为训练集和测试集

    Args:
        input_file: 输入CSV文件路径
        train_ratio: 训练集比例，默认%70
        random_state: 随机种子
    """
    # 读取数据
    print(f"读取数据文件: {input_file}")
    df = pd.read_csv(input_file)
    print(f"总数据量: {len(df)} 条")

    # 检查数据
    if 'label' not in df.columns:
        print("错误: 数据中缺少 'label' 列")
        return

    # 统计标签分布
    label_counts = df['label'].value_counts()
    print(f"\n标签分布:")
    for label, count in label_counts.items():
        print(f"  标签 {label}: {count} 条 ({count/len(df)*100:.2f}%)")

    # 分层采样分割（保持标签分布）
    train_df, test_df = train_test_split(
        df,
        train_size=train_ratio,
        random_state=random_state,
        stratify=df['label']  # 分层采样
    )

    print(f"\n分割结果:")
    print(f"  训练集: {len(train_df)} 条 ({len(train_df)/len(df)*100:.2f}%)")
    print(f"  测试集: {len(test_df)} 条 ({len(test_df)/len(df)*100:.2f}%)")

    # 保存文件
    base_name = os.path.splitext(input_file)[0]
    train_file = f"{base_name}_train.csv"
    test_file = f"{base_name}_test.csv"

    train_df.to_csv(train_file, index=False)
    test_df.to_csv(test_file, index=False)

    print(f"\n已保存:")
    print(f"  训练集: {train_file}")
    print(f"  测试集: {test_file}")

    # 验证分割后的标签分布
    print(f"\n训练集标签分布:")
    train_label_counts = train_df['label'].value_counts()
    for label, count in train_label_counts.items():
        print(f"  标签 {label}: {count} 条 ({count/len(train_df)*100:.2f}%)")

    print(f"\n测试集标签分布:")
    test_label_counts = test_df['label'].value_counts()
    for label, count in test_label_counts.items():
        print(f"  标签 {label}: {count} 条 ({count/len(test_df)*100:.2f}%)")

    return train_file, test_file

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='将CSV数据集分割为训练集和测试集')
    parser.add_argument('input', help='输入CSV文件路径')
    parser.add_argument('--ratio', type=float, default=0.7, help='训练集比例')
    parser.add_argument('--seed', type=int, default=1, help='随机种子')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"错误: 文件 {args.input} 不存在")
    else:
        split_train_test(args.input, train_ratio=args.ratio, random_state=args.seed)