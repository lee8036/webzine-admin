//JWT 모듈을 추가
const jwt = require('jsonwebtoken');

//JWT토큰 유효성 검사 공통모듈
exports.verifyToken = (req,res,next) =>{

    try{
        //jwt.verify메소드('브라우저에서 전달되는 토큰','서버에 저장해 둔 토큰발급인증키값')로 토큰 유효성을 검사
        //jwt.verify메소드는 실행 후 토큰 내 페이로드에 저장되어있는 사용자정보를 디코딩해서 반환
        //검사 후 반환되는 디코디드 된 사용자 저장값을 req.decoded에 저장한다
        req.decoded = jwt.verify(req.headers.authorization,process.env.JWT_SECRET);
        return next();
    }catch(err){
        if(err.name === 'TokenExpiredError');
            return res.status(419).json({
                code:419,
                message:'인증토큰 만료'
            });
    }
      return res.status(401).json({
                code:401,
                message:'유효하지 않은 토큰'

};