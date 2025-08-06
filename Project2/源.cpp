#include <opencv2/opencv.hpp>
#include <iostream>
#include <string>

using namespace cv;
using namespace std;

// ���ˮӡ����
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

// ��ȡˮӡ����
bool extractWatermark(const Mat& src, const Mat& original, string& extractedText) {
    Rect watermarkRegion(src.cols - 200, src.rows - 30, 200, 30);
    Mat watermarked = src(watermarkRegion).clone();
    Mat originalRegion = original(watermarkRegion).clone();

    Mat diff;
    absdiff(watermarked, originalRegion, diff);

    // ת��Ϊ�Ҷ�ͼ��
    Mat diffGray;
    cvtColor(diff, diffGray, COLOR_BGR2GRAY);

    // Ӧ����ֵ�Ի�ö�ֵͼ��
    Mat thresh;
    threshold(diffGray, thresh, 50, 255, THRESH_BINARY);

    // ���������������
    double nonZeroCount = countNonZero(thresh);
    if (nonZeroCount > (thresh.rows * thresh.cols * 0.1)) { // 10%�������б仯
        extractedText = "Watermark detected";
        return true;
    }
    else {
        extractedText = "No watermark detected";
        return false;
    }
}

// ³���Բ��Ժ���
void robustnessTest(const Mat& original, const Mat& watermarked) {
    std::vector<Mat> tests;
    string testName;
    Mat testImage;

    // ��ת����
    testImage = watermarked.clone();
    flip(testImage, testImage, 1); // ˮƽ��ת
    tests.push_back(testImage);
    testName = "Flipped";
    // ��ȡˮӡ
    string extracted;
    bool detected = extractWatermark(testImage, original, extracted);
    cout << testName << " Image: " << extracted << endl;
    imwrite(testName + "_image.jpg", testImage); // �������ͼ��

    // ƽ�Ʋ���
    testImage = watermarked.clone();
    testImage = testImage(Rect(50, 50, testImage.cols - 100, testImage.rows - 100)).clone(); // ��ȡ���Ĳ���
    tests.push_back(testImage);
    testName = "Translated";
    detected = extractWatermark(testImage, original, extracted);
    cout << testName << " Image: " << extracted << endl;
    imwrite(testName + "_image.jpg", testImage); // �������ͼ��

    // ��ȡ����
    testImage = watermarked.clone();
    testImage = testImage(Rect(100, 100, 200, 200)).clone(); // ��ȡһ����
    tests.push_back(testImage);
    testName = "Cropped";
    detected = extractWatermark(testImage, original, extracted);
    cout << testName << " Image: " << extracted << endl;
    imwrite(testName + "_image.jpg", testImage); // �������ͼ��

    // �����ԱȶȲ���
    testImage = watermarked.clone();
    testImage.convertTo(testImage, -1, 1.5, 0); // ���ӶԱȶ�
    tests.push_back(testImage);
    testName = "Contrast Adjusted";
    detected = extractWatermark(testImage, original, extracted);
    cout << testName << " Image: " << extracted << endl;
    imwrite(testName + "_image.jpg", testImage); // �������ͼ��
}

int main(int argc, char** argv) {
    if (argc != 2) {
        cout << "Usage: ./watermark <D:/vs_code/Project2/1005.jpg>" << endl;
        return -1;
    }

    // �������в�����ȡ·��
    string imagePath = string(argv[1]);

    Mat original = imread(imagePath);
    if (original.empty()) {
        cout << "�޷�����ͼ��: " << imagePath << endl;
        return -1;
    }

    Mat watermarked;
    addWatermark(original, watermarked, "Eux");
    imwrite("watermarked_image.jpg", watermarked);
    cout << "��ˮӡ��ͼ���ѱ���Ϊ watermarked_image.jpg" << endl;

    // ����³���Բ��Բ��������ͼ��
    robustnessTest(original, watermarked);

    return 0;
}