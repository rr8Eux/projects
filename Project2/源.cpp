#include <opencv2/opencv.hpp>
#include <iostream>
#include <string>

using namespace cv;
using namespace std;

// 添加水印函数
void addWatermark(const Mat& src, Mat& dst, const string& watermarkText) {
    dst = src.clone();

    int fontFace = FONT_HERSHEY_SIMPLEX;
    double fontScale = 1.0;
    int thickness = 2;
    Scalar textColor(255, 255, 255);
    Point textOrg(dst.cols - 200, dst.rows - 30);

    putText(dst, watermarkText, textOrg, fontFace, fontScale, textColor, thickness, LINE_AA);

    Rect roi(textOrg.x, textOrg.y - 30, 200, 30);
    Mat semiTransparent = Mat::zeros(dst.size(), dst.type());
    addWeighted(dst(roi), 0.7, semiTransparent(roi), 0.3, 0, dst(roi));
}

// 提取水印函数
bool extractWatermark(const Mat& src, const Mat& original, string& extractedText) {
    Rect watermarkRegion(src.cols - 200, src.rows - 30, 200, 30);
    Mat watermarked = src(watermarkRegion).clone();
    Mat originalRegion = original(watermarkRegion).clone();

    Mat diff;
    absdiff(watermarked, originalRegion, diff);

    // 转换为灰度图像
    Mat diffGray;
    cvtColor(diff, diffGray, COLOR_BGR2GRAY);

    // 应用阈值以获得二值图像
    Mat thresh;
    threshold(diffGray, thresh, 50, 255, THRESH_BINARY);

    // 计算非零像素数量
    double nonZeroCount = countNonZero(thresh);
    if (nonZeroCount > (thresh.rows * thresh.cols * 0.1)) { // 10%的像素有变化
        extractedText = "Watermark detected";
        return true;
    }
    else {
        extractedText = "No watermark detected";
        return false;
    }
}

// 鲁棒性测试函数
void robustnessTest(const Mat& original, const Mat& watermarked) {
    std::vector<Mat> tests;
    string testName;
    Mat testImage;

    // 翻转测试
    testImage = watermarked.clone();
    flip(testImage, testImage, 1); // 水平翻转
    tests.push_back(testImage);
    testName = "Flipped";
    // 提取水印
    string extracted;
    bool detected = extractWatermark(testImage, original, extracted);
    cout << testName << " Image: " << extracted << endl;
    imwrite(testName + "_image.jpg", testImage); // 保存测试图像

    // 平移测试
    testImage = watermarked.clone();
    testImage = testImage(Rect(50, 50, testImage.cols - 100, testImage.rows - 100)).clone(); // 截取中心部分
    tests.push_back(testImage);
    testName = "Translated";
    detected = extractWatermark(testImage, original, extracted);
    cout << testName << " Image: " << extracted << endl;
    imwrite(testName + "_image.jpg", testImage); // 保存测试图像

    // 截取测试
    testImage = watermarked.clone();
    testImage = testImage(Rect(100, 100, 200, 200)).clone(); // 截取一部分
    tests.push_back(testImage);
    testName = "Cropped";
    detected = extractWatermark(testImage, original, extracted);
    cout << testName << " Image: " << extracted << endl;
    imwrite(testName + "_image.jpg", testImage); // 保存测试图像

    // 调整对比度测试
    testImage = watermarked.clone();
    testImage.convertTo(testImage, -1, 1.5, 0); // 增加对比度
    tests.push_back(testImage);
    testName = "Contrast Adjusted";
    detected = extractWatermark(testImage, original, extracted);
    cout << testName << " Image: " << extracted << endl;
    imwrite(testName + "_image.jpg", testImage); // 保存测试图像
}

int main(int argc, char** argv) {
    if (argc != 2) {
        cout << "Usage: ./watermark <D:/vs_code/Project2/1005.jpg>" << endl;
        return -1;
    }

    // 从命令行参数获取路径
    string imagePath = string(argv[1]);

    Mat original = imread(imagePath);
    if (original.empty()) {
        cout << "无法加载图像: " << imagePath << endl;
        return -1;
    }

    Mat watermarked;
    addWatermark(original, watermarked, "Eux");
    imwrite("watermarked_image.jpg", watermarked);
    cout << "带水印的图像已保存为 watermarked_image.jpg" << endl;

    // 进行鲁棒性测试并保存测试图像
    robustnessTest(original, watermarked);

    return 0;
}