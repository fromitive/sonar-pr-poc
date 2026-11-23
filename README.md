## SonarQube Community 버전 PR 단위 점검 Poc

* SonarQube Community는 브랜치 1개만 분석 결과 제공
* 형상관리를 할때는 PR 단위로 보안점검을 수행할 수 없음
* PR 단위로 하려면 SonarQube Develop 플랜이 필요하나, 코드가 점점 많아질수록 라이센스 비용이 추가로 드는 경우가 있음
* 따라서 SonarQube Develop 플랜을 사용하지 않으면서도 Community 기능을 이용한 PR 단위 리뷰가 가능한지 확인하기 위해 이 레포를 구축함