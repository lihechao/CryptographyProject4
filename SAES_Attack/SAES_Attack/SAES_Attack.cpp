#include "stdafx.h"
#include "S-AES.h"
void CrackKey(BYTE PlainText[2][2],BYTE CipherText[2][2],int Counter[4][16]);
int main()
{
	printf("\t\t——————对1轮SAES进行差分攻击——————\n\n");
label:while(1)
	  {
		  int i,j,k,l,Counter[4][16]={0};/*每个半字节可能的值计数，计数值越大可能性越大*/
		  int PossibleKeyNum[4]={0};/*四个半字节分别可能的密钥结果数*/
		  HALFBYTE PossibleKey[4][2]={0};/*四个半字节密钥的可能值，每个半字节最多有两种可能*/
		  BYTE PlainText[2][2]={0},CipherText[2][2]={0};
		  BYTE Key[2]={0};/*最终破解出的密钥*/
		  printf("\n请输入明密文对（十六进制格式，八位间以空白字符分隔，如AB CD）:\n");
		  printf("明文1：");
		  while (!scanf("%x%x",&PlainText[0][0],&PlainText[0][1]))
		  {
			  fflush(stdin);
			  printf("您输入的明文有误，请重新输入：\n明文1：");
		  }
		  printf("密文1：");
		  while (!scanf("%x%x",&CipherText[0][0],&CipherText[0][1]))
		  {
			  fflush(stdin);
			  printf("您输入的密文有误，请重新输入：\n密文1：");
		  }
		  printf("明文2：");
		  while (!scanf("%x%x",&PlainText[1][0],&PlainText[1][1]))
		  {
			  fflush(stdin);
			  printf("您输入的明文有误，请重新输入：\n明文2：");
		  }
		  printf("密文2：");
		  while (!scanf("%x%x",&CipherText[1][0],&CipherText[1][1]))
		  {
			  fflush(stdin);
			  printf("您输入的密文有误，请重新输入：\n密文2：");
		  }
		  CrackKey(PlainText,CipherText,Counter);
		  for (i=0;i<4;i++)
		  {
			  for (j=0;j<16;j++)
			  {
				  if (2==Counter[i][j])
				  {
					  PossibleKey[i][PossibleKeyNum[i]++]=j;
				  }
			  }
		  }
		  for (i=0;i<PossibleKeyNum[0];i++)/*从可能密钥搜索正确密钥，把每个半字节的可能值拼在一起对某明文加密如果得到对应密文即为正确*/
		  {
			  for (j=0;j<PossibleKeyNum[1];j++)
			  {
				  for (k=0;k<PossibleKeyNum[2];k++)
				  {
					  for (l=0;l<PossibleKeyNum[3];l++)
					  {
						  BYTE RoundKey[4],temp[2];
						  Key[0]=(PossibleKey[0][i]<<4)|(PossibleKey[1][j]);
						  Key[1]=(PossibleKey[2][k]<<4)|(PossibleKey[3][l]);
						  Extend_Key(Key,RoundKey);
						  EncryptBlock(PlainText[0],RoundKey,temp);
						  if (!memcmp(temp,CipherText[0],sizeof(BYTE)*2))
						  {
							  printf("破解出的密钥为：%X %X\n",Key[0],Key[1]);
							  goto label;/*破解完成即可进入下次破解*/
						  }
					  }
				  }
			  }
		  }
		  printf("破解失败！请检查明密文对是否有错！\n");
	  }
	  return 0;
}

/*******************************************************************/
/*函数功能：由一对明密文对破解密钥，将四个半字节密钥的可能值对应数字在
计数器Counter中加1
*/
/*******************************************************************/
void CrackKey(BYTE PlainText[2][2],BYTE CipherText[2][2],int Counter[4][16])
{
	BYTE CipherXor[2]={0},i;
	HALFBYTE State[2][2]={0};
	CipherXor[0]=CipherText[0][0]^CipherText[1][0];
	CipherXor[1]=CipherText[0][1]^CipherText[1][1];
	State[0][0]=CipherXor[0]>>4;/*取高四位*/
	State[1][0]=CipherXor[0]&0x0F;/*取低四位*/
	State[0][1]=CipherXor[1]>>4;
	State[1][1]=CipherXor[1]&0x0F;
	MixColumnsInverse(State);
	ShiftRows(State);
	for (i=0;i<=0x0F;i++)
	{
		if ((SBox_Inv[i>>2][i&0x03]^(PlainText[0][0]>>4))
			==(SBox_Inv[(i^State[0][0])>>2][(i^State[0][0])&0x03]^(PlainText[1][0]>>4)))
		{
			Counter[0][SBox_Inv[i>>2][i&0x03]^(PlainText[0][0]>>4)]++;
			Counter[0][SBox_Inv[i>>2][i&0x03]^(PlainText[1][0]>>4)]++;
		}
		if ((SBox_Inv[i>>2][i&0x03]^(PlainText[0][0]&0x0F))
			==(SBox_Inv[(i^State[1][0])>>2][(i^State[1][0])&0x03]^(PlainText[1][0]&0x0F)))
		{
			Counter[1][SBox_Inv[i>>2][i&0x03]^(PlainText[0][0]&0x0F)]++;
			Counter[1][SBox_Inv[i>>2][i&0x03]^(PlainText[1][0]&0x0F)]++;
		}
		if ((SBox_Inv[i>>2][i&0x03]^(PlainText[0][1]>>4))
			==(SBox_Inv[(i^State[0][1])>>2][(i^State[0][1])&0x03]^(PlainText[1][1]>>4)))
		{
			Counter[2][SBox_Inv[i>>2][i&0x03]^(PlainText[0][1]>>4)]++;
			Counter[2][SBox_Inv[i>>2][i&0x03]^(PlainText[1][1]>>4)]++;
		}
		if ((SBox_Inv[i>>2][i&0x03]^(PlainText[0][1]&0x0F))
			==(SBox_Inv[(i^State[1][1])>>2][(i^State[1][1])&0x03]^(PlainText[1][1]&0x0F)))
		{
			Counter[3][SBox_Inv[i>>2][i&0x03]^(PlainText[0][1]&0x0F)]++;
			Counter[3][SBox_Inv[i>>2][i&0x03]^(PlainText[1][1]&0x0F)]++;
		}
	}
}